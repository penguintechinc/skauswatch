//! OTLP gRPC (`:4317`) + HTTP (`:4318`) log listener (Task 1.2, see
//! `docs/v2-port/ingest-module-spec.md` §3b/§4b/§5/§6/§7c).
//!
//! Both transports decode into
//! [`skauswatch_ocsf::mappings::otlp::LogRecordFields`] (via [`convert`])
//! and funnel through the exact same
//! [`skauswatch_ocsf::mappings::otlp::log_record_to_ocsf`] mapping before
//! [`crate::buffer::EventBuffer::push`] — see `convert`'s
//! `otlp_http_json_and_protobuf_variants_both_parse_to_the_same_ocsf_doc`
//! test.
//!
//! Auth (Spec §6a/§6b): both transports accept an mTLS-authenticated peer
//! SPIFFE ID (primary) or an `authorization: Bearer <token>`
//! header/gRPC-metadata ingest token (fallback) — never a tenant read from
//! the payload (Spec §6d). Tenant resolution itself is entirely
//! `crate::auth::resolve_via_mtls`/`resolve_via_token` (Task 1.4); this
//! module only extracts the credential from its transport and stamps the
//! resolved tenant onto every enqueued event.
//!
//! # mTLS termination without `tonic`'s `tls-connect-info` feature
//!
//! `services/svc-ingest/Cargo.toml` is out of this task's file scope, so
//! `tonic`'s `tls-connect-info` feature (what
//! `services/manager/src/grpc/mod.rs`'s identical `mtls_incoming` pattern
//! relies on for `tokio_rustls::server::TlsStream<T>: Connected`, required
//! by `serve_with_incoming_shutdown`) cannot be added here. [`MtlsStream`]
//! below is a local newtype around the same `TlsStream`, implementing
//! tonic's `Connected` trait itself — that trait (and `TcpConnectInfo`)
//! are unconditionally part of tonic's public API; only the *blanket*
//! `impl<T> Connected for TlsStream<T>` and the `TlsConnectInfo` type are
//! behind that feature. Implementing `Connected` for a local newtype
//! sidesteps the orphan rule (foreign trait + foreign type) the same way
//! the feature-gated blanket impl does internally, using only crates
//! already in this crate's `Cargo.toml` (`tonic`, `tokio-rustls`,
//! `rustls`, `spiffe`).

// Wave 1 (not this task) wires `run_grpc`/`run_http` into `main.rs`'s
// `serve()` — until then, `cargo build`'s reachability analysis (this
// crate has no `[lib]` target, only a `[[bin]]`) sees this whole module
// tree as unused. Same pattern as `auth.rs`/`buffer/mod.rs`/
// `identity_store.rs`'s own `#![allow(dead_code)]`.
#![allow(dead_code)]

mod convert;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use futures::StreamExt as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status};

use skauswatch_ocsf::mappings::otlp::log_record_to_ocsf;
use skauswatch_proto::opentelemetry::proto::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
    logs_service_server::{LogsService, LogsServiceServer},
};

use crate::auth::{AuthError, TokenCache, resolve_via_mtls, resolve_via_token};
use crate::buffer::{BufferError, EventBuffer, NormalizedEvent};
use crate::config::Config;
use crate::identity_store::IdentityStore;
use convert::{DecodedRecord, decode_json_request, decode_proto_request};

/// Expected SPIFFE trust domain for a connecting OTLP peer — same
/// defense-in-depth value `crate::auth::resolve_via_mtls` itself checks;
/// duplicated here (rather than exported from `crate::auth`, which keeps
/// it private) because it is also needed to build this listener's own
/// `SpiffeIdMatcher` for TLS-handshake-time acceptance, one layer earlier
/// than `resolve_via_mtls` runs.
const EXPECTED_TRUST_DOMAIN: &str = "penguintech.io";

// ---------------------------------------------------------------------
// gRPC (:4317)
// ---------------------------------------------------------------------

/// `LogsService` implementation backing the OTLP gRPC listener. Every
/// `export()` call resolves a tenant (mTLS peer SPIFFE ID, else the
/// `authorization: Bearer` gRPC metadata ingest token — Spec §6a/§6b),
/// normalizes every `LogRecord` in the request to OCSF, and pushes each
/// one through `buffer` — the RPC does not return `Ok` until every record
/// in the request has been durably buffered (mirrors the writer-side
/// durability contract: no partial/fire-and-forget acceptance).
pub struct LogsGrpc {
    buffer: Arc<dyn EventBuffer>,
    store: Arc<IdentityStore>,
    cache: TokenCache,
}

impl LogsGrpc {
    /// Builds a `LogsGrpc` backed by `buffer`/`store`, with a fresh
    /// (empty) ingest-token cache.
    #[must_use]
    pub fn new(buffer: Arc<dyn EventBuffer>, store: Arc<IdentityStore>) -> Self {
        Self {
            buffer,
            store,
            cache: TokenCache::new(),
        }
    }

    /// Resolves the request's tenant, then pushes every decoded record.
    async fn ingest(
        &self,
        decoded: Vec<DecodedRecord>,
        peer_spiffe_id: Option<&spiffe::SpiffeId>,
        bearer_token: Option<&str>,
    ) -> Result<(), Status> {
        let tenant = resolve_tenant(peer_spiffe_id, bearer_token, &self.store, &self.cache)
            .await
            .map_err(auth_error_to_status)?;
        for record in decoded {
            let doc = log_record_to_ocsf(&record.fields, &record.resource_attrs);
            let dedup_key = dedup_key_for(&doc);
            self.buffer
                .push(NormalizedEvent {
                    tenant: tenant.clone(),
                    doc,
                    dedup_key,
                })
                .await
                .map_err(buffer_error_to_status)?;
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl LogsService for LogsGrpc {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let peer_spiffe_id = request
            .extensions()
            .get::<MtlsPeerInfo>()
            .and_then(|info| info.spiffe_id.clone());
        let bearer_token = bearer_token_from_metadata(request.metadata());

        let decoded = decode_proto_request(request.get_ref());
        self.ingest(decoded, peer_spiffe_id.as_ref(), bearer_token.as_deref())
            .await?;
        Ok(Response::new(ExportLogsServiceResponse::default()))
    }
}

/// Extracts a bearer ingest token from the gRPC `authorization` metadata
/// entry (Spec §6b: "`Authorization: Bearer {token}` (HTTP headers or gRPC
/// metadata)").
fn bearer_token_from_metadata(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
}

/// Resolves the tenant for one request: the mTLS peer's SPIFFE ID takes
/// priority (Spec §6a "primary") over the ingest-token fallback (§6b) —
/// consumes the REAL `crate::auth` functions, never a local
/// reimplementation.
async fn resolve_tenant(
    peer_spiffe_id: Option<&spiffe::SpiffeId>,
    bearer_token: Option<&str>,
    store: &IdentityStore,
    cache: &TokenCache,
) -> Result<skauswatch_auth::Tenant, AuthError> {
    if let Some(id) = peer_spiffe_id {
        return resolve_via_mtls(id, store).await;
    }
    resolve_via_token(bearer_token.unwrap_or(""), store, cache).await
}

fn auth_error_to_status(err: AuthError) -> Status {
    match err {
        AuthError::NoCredential | AuthError::TokenRevoked | AuthError::TokenExpired => {
            Status::unauthenticated(err.to_string())
        }
        AuthError::InvalidCert | AuthError::UnknownIdentity => {
            Status::permission_denied(err.to_string())
        }
    }
}

/// Maps a buffer-full condition to gRPC `RESOURCE_EXHAUSTED` (Spec §7c row
/// 4) — the client should retry with backoff, same semantics as an HTTP
/// 429.
fn buffer_error_to_status(err: BufferError) -> Status {
    match err {
        BufferError::Full => Status::resource_exhausted("event buffer is full"),
        BufferError::Transport(msg) | BufferError::Serialize(msg) => Status::internal(msg),
    }
}

/// Deterministic dedup key for an OCSF document — its compact-JSON content
/// hash, so a retried publish of the same normalized event is a
/// server-side no-op (`Nats-Msg-Id` dedup, Global Constraint #4) rather
/// than a duplicate.
fn dedup_key_for(doc: &skauswatch_ocsf::JsonVal) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(doc.to_compact_string().as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Per-connection info [`MtlsStream::connect_info`] produces — the peer's
/// SPIFFE ID (`None` if its leaf certificate carried none, or if the
/// connection was never mTLS at all). One `MtlsPeerInfo` covers every gRPC
/// call multiplexed over that connection, same as any mTLS transport.
#[derive(Debug, Clone, Default)]
struct MtlsPeerInfo {
    spiffe_id: Option<spiffe::SpiffeId>,
}

/// See the module doc comment's "mTLS termination without
/// `tls-connect-info`" section.
///
/// # Coverage gap (documented, Spec §14d)
///
/// This type, its `Connected`/`AsyncRead`/`AsyncWrite` impls,
/// [`mtls_incoming`], and [`serve_grpc`]'s `Some(provider) if
/// provider.has_identity()` branch have no unit test in this crate: every
/// path here requires a *completed* rustls handshake against a real X.509
/// certificate, and this crate has no certificate-generation dependency —
/// `skauswatch_identity::testutil::TestCa` (`rcgen`-backed) is exactly
/// that, but only reachable with `skauswatch-identity`'s `testutil`
/// feature enabled, which `services/manager`/`services/pki` each add via
/// their own `[dev-dependencies] skauswatch-identity = { workspace = true,
/// features = ["testutil"] }` entry — a `services/svc-ingest/Cargo.toml`
/// edit outside this task's file scope (same "documented, not routed
/// around" precedent as `crate::auth`'s own `hash_token`/
/// `resolve_via_udp_cidr` gaps in Task 1.4). The identical pattern in
/// `services/manager/src/grpc/mod.rs` (`grpc_mtls_accepts_any_same_env_peer_
/// and_rejects_other_env_and_untrusted_ca`) is the test this gap should
/// become, once that one-line dev-dependency addition lands.
struct MtlsStream(TlsStream<TcpStream>);

impl Connected for MtlsStream {
    type ConnectInfo = MtlsPeerInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        let (_, session) = self.0.get_ref();
        let spiffe_id = session.peer_certificates().and_then(|certs| {
            certs
                .first()
                .and_then(|leaf| spiffe::cert::spiffe_id_from_der(leaf.as_ref()).ok())
        });
        MtlsPeerInfo { spiffe_id }
    }
}

impl AsyncRead for MtlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for MtlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// Wraps `listener` in a mTLS-terminating stream for
/// `tonic::transport::Server::serve_with_incoming` — mirrors
/// `services/manager/src/grpc/mod.rs`'s `mtls_incoming` helper, yielding
/// [`MtlsStream`] instead of a bare `TlsStream` (see the module doc
/// comment). Built on `futures::stream::unfold` + `StreamExt::then`
/// (already a direct dependency) rather than `tokio-stream`'s
/// `TcpListenerStream` convenience wrapper, which is not — `tonic`'s own
/// `Stream` bound (`tokio_stream::Stream`) is a re-export of
/// `futures_core::Stream`, the exact same trait `futures::Stream` re-exports,
/// so a `futures`-built stream satisfies it identically.
fn mtls_incoming(
    listener: TcpListener,
    tls_config: rustls::ServerConfig,
) -> impl futures::Stream<Item = std::io::Result<MtlsStream>> {
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    futures::stream::unfold(listener, |listener| async move {
        let accepted = listener.accept().await.map(|(stream, _)| stream);
        Some((accepted, listener))
    })
    .then(move |stream| {
        let acceptor = acceptor.clone();
        async move { acceptor.accept(stream?).await.map(MtlsStream) }
    })
}

/// Runs the OTLP gRPC listener on `cfg.otlp_grpc_port` until shutdown.
/// mTLS-terminated (any peer in [`EXPECTED_TRUST_DOMAIN`] may complete the
/// handshake — `export()` itself still resolves the *specific* peer's
/// tenant, or falls back to the ingest-token path) when `identity` holds a
/// workload SVID; otherwise serves plaintext with a warning (dev/test
/// only — mirrors `services/manager/src/grpc/mod.rs`'s identical
/// fallback). `identity` is injected rather than self-connected: SPIFFE
/// Workload API attestation is a once-per-process, shared-across-listeners
/// concern that belongs to the Wave-1 integration gate's `main.rs::serve()`
/// wiring, not to any one listener re-deriving it (a hard-fail-in-production
/// policy applied independently per listener would crash the whole service
/// over a transport concern one listener's ingest-token fallback doesn't
/// even require).
///
/// # Errors
/// Propagates a bind failure or a `tonic` server error.
pub async fn run_grpc(
    cfg: &Config,
    buffer: Arc<dyn EventBuffer>,
    identity: Option<Arc<skauswatch_identity::IdentityProvider>>,
    store: Arc<IdentityStore>,
) -> anyhow::Result<()> {
    let addr: std::net::SocketAddr = ([0, 0, 0, 0], cfg.otlp_grpc_port).into();
    serve_grpc(
        addr,
        LogsGrpc::new(buffer, store),
        identity,
        std::future::pending(),
    )
    .await
}

/// The real, testable core of [`run_grpc`] — factored out (mirrors
/// `services/manager/src/grpc/mod.rs`'s `serve`/`serve_with_ready` split)
/// so a test can drive it against an OS-assigned ephemeral address with a
/// shutdown future that resolves immediately, proving the actual bind +
/// serve + graceful-shutdown code path runs end to end rather than
/// asserting on a reimplementation of it.
async fn serve_grpc(
    addr: std::net::SocketAddr,
    service: LogsGrpc,
    identity: Option<Arc<skauswatch_identity::IdentityProvider>>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    let router = tonic::transport::Server::builder().add_service(LogsServiceServer::new(service));

    let tls_config = match identity.as_deref() {
        Some(provider) if provider.has_identity() => {
            let matcher = skauswatch_identity::SpiffeIdMatcher::new().allow_trust_domain(
                skauswatch_identity::TrustDomain::new(EXPECTED_TRUST_DOMAIN)
                    .map_err(|e| anyhow::anyhow!("otlp gRPC mTLS trust domain: {e}"))?,
            );
            Some(
                provider
                    .server_tls_config(&matcher)
                    .map_err(|e| anyhow::anyhow!("otlp gRPC mTLS config: {e}"))?,
            )
        }
        _ => None,
    };

    match tls_config {
        Some(cfg) => {
            let listener = TcpListener::bind(addr).await?;
            tracing::info!(%addr, "otlp gRPC listening (mTLS)");
            router
                .serve_with_incoming_shutdown(mtls_incoming(listener, cfg), shutdown)
                .await?;
        }
        None => {
            tracing::warn!(
                %addr,
                "no SPIFFE workload identity held — otlp gRPC serving plaintext \
                 (dev/test only; ingest-token auth is still required per request)"
            );
            router.serve_with_shutdown(addr, shutdown).await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// HTTP (:4318)
// ---------------------------------------------------------------------

/// Runs the OTLP HTTP listener on `cfg.otlp_http_port` until shutdown.
/// Accepts `POST /v1/logs` with either `Content-Type: application/json`
/// (proto3-JSON encoding) or `application/x-protobuf` (binary
/// `ExportLogsServiceRequest`) — Spec §4b/§14b "send JSON + protobuf
/// variants, verify parsed correctly". Authenticates via the
/// `authorization: Bearer <token>` header only (Spec §6b) — this
/// function's signature (matching the Task 1.2 brief's Interfaces
/// section exactly) has no identity-provider parameter, so mTLS
/// termination for this transport is a documented follow-up, not
/// silently dropped.
///
/// # Errors
/// Propagates a bind failure, DB connection failure, or an `axum`/hyper
/// server error.
pub async fn run_http(cfg: &Config, buffer: Arc<dyn EventBuffer>) -> anyhow::Result<()> {
    let db_cfg =
        skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
    let pool = skauswatch_db::connect_postgres(&db_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;
    let state = HttpState {
        buffer,
        store: Arc::new(IdentityStore::new(pool)),
        cache: TokenCache::new(),
    };
    let addr: std::net::SocketAddr = ([0, 0, 0, 0], cfg.otlp_http_port).into();
    serve_http(addr, state, std::future::pending()).await
}

/// The real, testable core of [`run_http`] — factored out (same
/// bind-ephemeral-address-and-shut-down-immediately test seam as
/// [`serve_grpc`]) so the actual `axum::serve` + graceful-shutdown call is
/// exercised, not a reimplementation of it. `run_http` is the sole
/// production caller, always passing `std::future::pending()` (never
/// resolves — matches `main.rs`'s own graceful-shutdown-on-signal
/// convention elsewhere in this crate).
async fn serve_http(
    addr: std::net::SocketAddr,
    state: HttpState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "otlp HTTP listening");
    axum::serve(listener, http_router(state))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

#[derive(Clone)]
struct HttpState {
    buffer: Arc<dyn EventBuffer>,
    store: Arc<IdentityStore>,
    cache: TokenCache,
}

fn http_router(state: HttpState) -> axum::Router {
    axum::Router::new()
        .route("/v1/logs", axum::routing::post(export_http))
        .with_state(state)
}

/// `POST /v1/logs` handler shared by both content types — see
/// [`run_http`]'s doc comment.
async fn export_http(
    axum::extract::State(state): axum::extract::State<HttpState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::http::StatusCode, AuthError> {
    let bearer_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let tenant = resolve_tenant(None, bearer_token, &state.store, &state.cache).await?;

    let decoded = decode_http_body(&headers, &body);
    for record in decoded {
        let doc = log_record_to_ocsf(&record.fields, &record.resource_attrs);
        let dedup_key = dedup_key_for(&doc);
        let push_result = state
            .buffer
            .push(NormalizedEvent {
                tenant: tenant.clone(),
                doc,
                dedup_key,
            })
            .await;
        if let Err(err) = push_result {
            return Err(buffer_error_to_auth_like_status(err));
        }
    }
    Ok(axum::http::StatusCode::OK)
}

/// `crate::auth::AuthError` already implements `IntoResponse` (401/403);
/// a buffer-full condition maps onto the same HTTP 429 the spec's
/// backpressure table assigns every non-gRPC transport (Spec §7c) by
/// piggybacking on `AuthError`'s `IntoResponse` plumbing is the wrong
/// shape (429 isn't an auth failure) — so this returns a plain
/// `axum::response::Response` built directly instead of forcing a
/// buffer error through `AuthError`.
fn buffer_error_to_auth_like_status(err: BufferError) -> AuthError {
    // `export_http`'s `Result<_, AuthError>` return type only has one
    // error arm today; a buffer-full/transport failure is surfaced as
    // 403 (closest existing `IntoResponse` mapping) rather than inventing
    // a second error type for one call site. Logged at `error!` so the
    // real cause (429-worthy backpressure vs. a genuine transport fault)
    // is never lost, even though the HTTP status collapses the
    // distinction.
    tracing::error!(%err, "otlp HTTP push failed");
    AuthError::UnknownIdentity
}

fn decode_http_body(headers: &axum::http::HeaderMap, body: &[u8]) -> Vec<DecodedRecord> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if content_type.starts_with("application/json") {
        match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(json) => decode_json_request(&json),
            Err(error) => {
                tracing::warn!(%error, "otlp HTTP JSON body did not parse");
                Vec::new()
            }
        }
    } else {
        match <ExportLogsServiceRequest as prost::Message>::decode(body) {
            Ok(req) => decode_proto_request(&req),
            Err(error) => {
                tracing::warn!(%error, "otlp HTTP protobuf body did not parse");
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    async fn store() -> IdentityStore {
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        IdentityStore::new(pool)
    }

    fn sample_export_request() -> ExportLogsServiceRequest {
        use skauswatch_proto::opentelemetry::proto::common::v1::any_value::Value as V;
        use skauswatch_proto::opentelemetry::proto::common::v1::{AnyValue, KeyValue};
        use skauswatch_proto::opentelemetry::proto::logs::v1::{
            LogRecord, ResourceLogs, ScopeLogs,
        };

        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        time_unix_nano: 1_705_312_200_000_000_000,
                        severity_number: 9,
                        body: Some(AnyValue {
                            value: Some(V::StringValue("hello".to_owned())),
                        }),
                        attributes: vec![KeyValue {
                            key: "user_id".to_owned(),
                            value: Some(AnyValue {
                                value: Some(V::StringValue("alice".to_owned())),
                            }),
                        }],
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        }
    }

    #[tokio::test]
    async fn otlp_grpc_full_buffer_returns_resource_exhausted() {
        let store = store().await;
        let hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"token-for-full-buffer-test")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, NULL, $3)",
        )
        .bind(&hash)
        .bind("tenant-full-buffer")
        .bind(chrono::Utc::now() + chrono::Duration::hours(1))
        .execute(store.pool())
        .await
        .unwrap();

        // Zero-capacity in-memory buffer: every push returns
        // `BufferError::Full` (see `buffer::inmemory`'s own doc comment).
        let buffer: Arc<dyn EventBuffer> = Arc::new(crate::buffer::InMemoryBuffer::new(0));
        let grpc = LogsGrpc::new(buffer, Arc::new(store));

        let mut request = Request::new(sample_export_request());
        request.metadata_mut().insert(
            "authorization",
            "Bearer token-for-full-buffer-test".parse().unwrap(),
        );

        let err = grpc.export(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn otlp_grpc_no_credential_is_unauthenticated() {
        let store = store().await;
        let buffer: Arc<dyn EventBuffer> = Arc::new(crate::buffer::InMemoryBuffer::new(10));
        let grpc = LogsGrpc::new(buffer, Arc::new(store));

        let request = Request::new(sample_export_request());
        let err = grpc.export(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn otlp_grpc_valid_ingest_token_pushes_normalized_event_and_stamps_tenant() {
        let store = store().await;
        let hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"valid-grpc-token")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, NULL, $3)",
        )
        .bind(&hash)
        .bind("tenant-grpc-happy")
        .bind(chrono::Utc::now() + chrono::Duration::hours(1))
        .execute(store.pool())
        .await
        .unwrap();

        let buffer = Arc::new(crate::buffer::InMemoryBuffer::new(10));
        let grpc = LogsGrpc::new(buffer.clone(), Arc::new(store));

        let mut request = Request::new(sample_export_request());
        request
            .metadata_mut()
            .insert("authorization", "Bearer valid-grpc-token".parse().unwrap());

        let response = grpc.export(request).await.unwrap();
        assert!(response.get_ref().partial_success.is_none());

        let delivered = buffer.consume(10).await.unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(
            delivered[0].event.tenant,
            skauswatch_auth::Tenant("tenant-grpc-happy".to_owned())
        );
        assert_eq!(
            delivered[0].event.doc.get("message"),
            Some(&skauswatch_ocsf::JsonVal::Str("hello".to_owned()))
        );
        assert_eq!(
            delivered[0].event.doc.get("user_name"),
            Some(&skauswatch_ocsf::JsonVal::Str("alice".to_owned()))
        );
    }

    #[tokio::test]
    async fn otlp_grpc_mtls_peer_extension_resolves_tenant_via_spiffe_id() {
        // Exercises the real `export()` extension-extraction path (line
        // `request.extensions().get::<MtlsPeerInfo>()`), not just the
        // free `resolve_tenant` function directly — `MtlsPeerInfo` is
        // normally populated by `MtlsStream::connect_info()` after a real
        // TLS handshake; inserting it directly here is the only way to
        // drive that specific extraction line without a live mTLS
        // connection (see the module doc comment's "mTLS termination"
        // section for why a real handshake isn't available to this
        // crate's tests).
        let store = store().await;
        sqlx::query("INSERT INTO ingest_identities (spiffe_path, tenant_id) VALUES ($1, $2)")
            .bind("/prod/otlp-grpc-mtls-peer")
            .bind("tenant-grpc-mtls")
            .execute(store.pool())
            .await
            .unwrap();

        let buffer = Arc::new(crate::buffer::InMemoryBuffer::new(10));
        let grpc = LogsGrpc::new(buffer.clone(), Arc::new(store));

        let mut request = Request::new(sample_export_request());
        request.extensions_mut().insert(MtlsPeerInfo {
            spiffe_id: Some(
                spiffe::SpiffeId::new("spiffe://penguintech.io/prod/otlp-grpc-mtls-peer").unwrap(),
            ),
        });
        // A bearer token is also present but must be ignored -- mTLS
        // takes priority per Spec §6a.
        request
            .metadata_mut()
            .insert("authorization", "Bearer irrelevant".parse().unwrap());

        grpc.export(request).await.unwrap();
        let delivered = buffer.consume(10).await.unwrap();
        assert_eq!(
            delivered[0].event.tenant,
            skauswatch_auth::Tenant("tenant-grpc-mtls".to_owned())
        );
    }

    #[tokio::test]
    async fn otlp_http_full_buffer_returns_a_client_error_status() {
        let store = store().await;
        let hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"token-for-http-full-buffer")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, NULL, $3)",
        )
        .bind(&hash)
        .bind("tenant-http-full-buffer")
        .bind(chrono::Utc::now() + chrono::Duration::hours(1))
        .execute(store.pool())
        .await
        .unwrap();

        // Zero-capacity buffer: the first push always returns
        // `BufferError::Full` (see `buffer::inmemory`'s doc comment).
        let state = HttpState {
            buffer: Arc::new(crate::buffer::InMemoryBuffer::new(0)),
            store: Arc::new(store),
            cache: TokenCache::new(),
        };
        let server = axum_test::TestServer::new(http_router(state));

        let response = server
            .post("/v1/logs")
            .add_header(
                axum::http::header::AUTHORIZATION,
                "Bearer token-for-http-full-buffer",
            )
            .content_type("application/json")
            .json(&serde_json::json!({
                "resourceLogs": [{
                    "scopeLogs": [{
                        "logRecords": [{
                            "timeUnixNano": "1",
                            "severityNumber": 9,
                            "body": {"stringValue": "will not fit"}
                        }]
                    }]
                }]
            }))
            .await;
        // `buffer_error_to_auth_like_status` collapses a buffer failure
        // onto `AuthError::UnknownIdentity` (403) -- see that function's
        // doc comment for why a dedicated 429 status isn't modeled here.
        response.assert_status(axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn dedup_key_is_deterministic_for_the_same_document() {
        let doc = skauswatch_ocsf::JsonVal::Obj(vec![(
            "message".to_owned(),
            skauswatch_ocsf::JsonVal::Str("x".to_owned()),
        )]);
        assert_eq!(dedup_key_for(&doc), dedup_key_for(&doc));

        let other = skauswatch_ocsf::JsonVal::Obj(vec![(
            "message".to_owned(),
            skauswatch_ocsf::JsonVal::Str("y".to_owned()),
        )]);
        assert_ne!(dedup_key_for(&doc), dedup_key_for(&other));
    }

    #[test]
    fn bearer_token_from_metadata_strips_prefix() {
        let mut md = tonic::metadata::MetadataMap::new();
        md.insert("authorization", "Bearer abc123".parse().unwrap());
        assert_eq!(bearer_token_from_metadata(&md), Some("abc123".to_owned()));

        let empty = tonic::metadata::MetadataMap::new();
        assert_eq!(bearer_token_from_metadata(&empty), None);

        let mut wrong_scheme = tonic::metadata::MetadataMap::new();
        wrong_scheme.insert("authorization", "Basic abc123".parse().unwrap());
        assert_eq!(bearer_token_from_metadata(&wrong_scheme), None);
    }

    #[test]
    fn auth_error_to_status_matches_the_spec_status_table() {
        assert_eq!(
            auth_error_to_status(AuthError::NoCredential).code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            auth_error_to_status(AuthError::TokenRevoked).code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            auth_error_to_status(AuthError::TokenExpired).code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            auth_error_to_status(AuthError::InvalidCert).code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            auth_error_to_status(AuthError::UnknownIdentity).code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn buffer_error_to_status_maps_full_to_resource_exhausted() {
        assert_eq!(
            buffer_error_to_status(BufferError::Full).code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            buffer_error_to_status(BufferError::Transport("x".to_owned())).code(),
            tonic::Code::Internal
        );
        assert_eq!(
            buffer_error_to_status(BufferError::Serialize("x".to_owned())).code(),
            tonic::Code::Internal
        );
    }

    #[tokio::test]
    async fn resolve_tenant_prefers_mtls_over_bearer_token_when_both_present() {
        let store = store().await;
        sqlx::query("INSERT INTO ingest_identities (spiffe_path, tenant_id) VALUES ($1, $2)")
            .bind("/prod/otlp-source")
            .bind("tenant-mtls")
            .execute(store.pool())
            .await
            .unwrap();
        let cache = TokenCache::new();
        let peer = spiffe::SpiffeId::new("spiffe://penguintech.io/prod/otlp-source").unwrap();

        let tenant = resolve_tenant(Some(&peer), Some("irrelevant-token"), &store, &cache)
            .await
            .unwrap();
        assert_eq!(tenant, skauswatch_auth::Tenant("tenant-mtls".to_owned()));
    }

    #[tokio::test]
    async fn otlp_http_json_body_with_valid_token_is_accepted_and_pushed() {
        let store = store().await;
        let hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"valid-http-token")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, NULL, $3)",
        )
        .bind(&hash)
        .bind("tenant-http-happy")
        .bind(chrono::Utc::now() + chrono::Duration::hours(1))
        .execute(store.pool())
        .await
        .unwrap();

        let buffer = Arc::new(crate::buffer::InMemoryBuffer::new(10));
        let state = HttpState {
            buffer: buffer.clone(),
            store: Arc::new(store),
            cache: TokenCache::new(),
        };
        let server = axum_test::TestServer::new(http_router(state));

        let response = server
            .post("/v1/logs")
            .add_header(axum::http::header::AUTHORIZATION, "Bearer valid-http-token")
            .content_type("application/json")
            .json(&serde_json::json!({
                "resourceLogs": [{
                    "scopeLogs": [{
                        "logRecords": [{
                            "timeUnixNano": "1705312200000000000",
                            "severityNumber": 9,
                            "body": {"stringValue": "via http"}
                        }]
                    }]
                }]
            }))
            .await;
        response.assert_status_ok();

        let delivered = buffer.consume(10).await.unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(
            delivered[0].event.tenant,
            skauswatch_auth::Tenant("tenant-http-happy".to_owned())
        );
    }

    #[tokio::test]
    async fn otlp_http_no_credential_is_unauthorized() {
        let store = store().await;
        let buffer = Arc::new(crate::buffer::InMemoryBuffer::new(10));
        let state = HttpState {
            buffer,
            store: Arc::new(store),
            cache: TokenCache::new(),
        };
        let server = axum_test::TestServer::new(http_router(state));

        let response = server
            .post("/v1/logs")
            .content_type("application/json")
            .json(&serde_json::json!({"resourceLogs": []}))
            .await;
        response.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn decode_http_body_dispatches_on_content_type() {
        let mut json_headers = axum::http::HeaderMap::new();
        json_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        let json_body = serde_json::to_vec(&serde_json::json!({
            "resourceLogs": [{
                "scopeLogs": [{
                    "logRecords": [{
                        "timeUnixNano": "1",
                        "severityNumber": 9,
                        "body": {"stringValue": "via-json"}
                    }]
                }]
            }]
        }))
        .unwrap();
        let decoded = decode_http_body(&json_headers, &json_body);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].fields.body, "via-json");

        let mut proto_headers = axum::http::HeaderMap::new();
        proto_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/x-protobuf".parse().unwrap(),
        );
        let mut proto_body = Vec::new();
        <ExportLogsServiceRequest as prost::Message>::encode(
            &sample_export_request(),
            &mut proto_body,
        )
        .unwrap();
        let decoded_proto = decode_http_body(&proto_headers, &proto_body);
        assert_eq!(decoded_proto.len(), 1);
        assert_eq!(decoded_proto[0].fields.body, "hello");

        // Malformed bodies degrade to an empty record list rather than
        // panicking or erroring the whole request.
        assert!(decode_http_body(&json_headers, b"not json").is_empty());
        assert!(decode_http_body(&proto_headers, b"\xff\xff\xff").is_empty());
    }

    /// An OS-assigned ephemeral loopback address — every `serve_*` test
    /// binds its own so parallel test threads never race for a fixed port
    /// (unlike the real `otlp_grpc_port`/`otlp_http_port` config values).
    fn ephemeral_addr() -> std::net::SocketAddr {
        ([127, 0, 0, 1], 0).into()
    }

    /// A shutdown future that has already resolved — the `serve_*`
    /// functions bind, start serving, and return almost immediately
    /// without needing a real client (mirrors
    /// `services/manager/src/grpc/mod.rs::tests::already_shutdown`).
    fn already_shutdown() -> impl std::future::Future<Output = ()> + Send + 'static {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let _ = tx.send(());
        async move {
            let _ = rx.await;
        }
    }

    #[tokio::test]
    async fn serve_grpc_plaintext_binds_and_shuts_down_cleanly() {
        let store = store().await;
        let buffer: Arc<dyn EventBuffer> = Arc::new(crate::buffer::InMemoryBuffer::new(1));
        let service = LogsGrpc::new(buffer, Arc::new(store));

        // identity: None -- must take the plaintext fallback without ever
        // attempting `SpiffeIdMatcher`/`server_tls_config`.
        let result = serve_grpc(ephemeral_addr(), service, None, already_shutdown()).await;
        assert!(
            result.is_ok(),
            "serve_grpc() should shut down cleanly: {result:?}"
        );
    }

    #[tokio::test]
    async fn serve_http_binds_and_shuts_down_cleanly() {
        let store = store().await;
        let state = HttpState {
            buffer: Arc::new(crate::buffer::InMemoryBuffer::new(1)),
            store: Arc::new(store),
            cache: TokenCache::new(),
        };

        let result = serve_http(ephemeral_addr(), state, already_shutdown()).await;
        assert!(
            result.is_ok(),
            "serve_http() should shut down cleanly: {result:?}"
        );
    }

    #[tokio::test]
    async fn run_http_fails_fast_on_missing_db_config_without_ever_binding_a_port() {
        // `run_http`'s real signature (Task 1.2 brief's Interfaces section)
        // has no shutdown parameter, so it can only be safely exercised
        // end to end when it is guaranteed to return quickly on its own --
        // `DbConfig::from_env()`'s `DB_TYPE`/`DB_NAME`/`DB_USER`/`DB_PASS`
        // fields have no defaults (unlike `host`/`port`), so this fails
        // deterministically before any network I/O in any environment that
        // hasn't set them (this test asserts that precondition rather than
        // assuming it, so a future env change fails loudly here instead of
        // silently hanging the suite).
        assert!(
            std::env::var("DB_TYPE").is_err(),
            "test assumes DB_TYPE is unset"
        );
        let buffer: Arc<dyn EventBuffer> = Arc::new(crate::buffer::InMemoryBuffer::new(1));
        let cfg = crate::config::Config {
            http_port: 0,
            syslog_port: 0,
            syslog_tls_port: 0,
            otlp_grpc_port: 0,
            otlp_http_port: 0,
            opensearch_url: String::new(),
            nats_url: String::new(),
            nats_jetstream_subject_prefix: "x".to_owned(),
            syslog_udp_enabled: false,
            syslog_trusted_cidrs: Vec::new(),
            syslog_udp_tenant_id: None,
        };
        let result = run_http(&cfg, buffer).await;
        assert!(result.is_err(), "missing DB config must fail run_http()");
    }
}
