//! Minimal tonic client for the SPIRE Server Entry API
//! (`spire.api.server.entry.v1.Entry`) — `ListEntries` + `BatchUpdateEntry`
//! only, enough to apply skauswatch's admin-adjustable SVID TTL policy
//! (`docs/v2-port/service-auth-model.md`,
//! `k8s/helm/spire/README.md#admin-adjustable-svid-ttl`) to every
//! registration entry in the trust domain.
//!
//! Proto is a hand-trimmed, self-contained vendor of the upstream
//! `spire-api-sdk` definitions — see `proto/entry.proto`'s own doc comment
//! for the exact provenance/pin and why the published `spire-api` crate
//! (crates.io) isn't used directly: as of its `0.8.0` release it only
//! implements the SPIRE **Agent** Delegated Identity API, not the
//! **Server** Entry API this crate needs. The proto's `Entry` message type
//! is renamed `RegistrationEntry` on the Rust side only (to avoid
//! colliding with the `Entry` *service* name in the same collapsed proto
//! package — upstream avoids this by splitting the service and the
//! message across two different proto packages, which this trimmed,
//! single-file vendor doesn't bother replicating); message type names
//! never appear on the wire, so this has no wire-compatibility effect.
//!
//! Callers own mTLS: [`SpireEntryClient::connect_mtls`] takes a
//! caller-built `rustls::ClientConfig` and drives the TCP+TLS handshake
//! manually — mirroring `services/manager/src/grpc/mod.rs`'s server-side
//! `mtls_incoming` helper — rather than depending on tonic's own TLS
//! feature (this workspace's mTLS config is always built by
//! `skauswatch-identity`, never tonic's `ClientTlsConfig`). This crate has
//! no dependency on `skauswatch-identity` itself; the caller (manager) is
//! responsible for building that `ClientConfig` and for holding an
//! X.509-SVID whose registration entry SPIRE trusts as "local or admin"
//! for this API.

#![allow(
    clippy::missing_errors_doc,
    clippy::doc_markdown,
    missing_docs,
    unused_qualifications
)] // pb module below is generated code

pub mod pb {
    tonic::include_proto!("spire.api.server.entry.v1");
}

use std::sync::Arc;
use std::time::Duration;

use pb::entry_client::EntryClient;
use pb::{BatchUpdateEntryRequest, EntryMask, ListEntriesRequest, RegistrationEntry};
use tonic::transport::{Channel, Endpoint};

/// Hard cap on `ListEntries` pagination loops — a defensive bound against a
/// misbehaving/malicious server returning a `next_page_token` forever;
/// SPIRE trust domains in this product are not expected to hold anywhere
/// near this many registration entries.
const MAX_LIST_PAGES: u32 = 10_000;

/// Errors raised while applying the SVID TTL policy via the SPIRE Server
/// Entry API. Every variant here is treated by callers as "not yet
/// applied" (fail-safe, never fatal) — see
/// `docs/v2-port/service-auth-model.md`.
#[derive(Debug, thiserror::Error)]
pub enum SpireEntryError {
    /// `server_addr`'s host portion is not a valid TLS server name.
    #[error("invalid SPIRE server hostname in {0:?}: {1}")]
    InvalidServerName(String, #[source] rustls::pki_types::InvalidDnsNameError),
    /// `server_addr` did not form a valid gRPC endpoint URI.
    #[error("invalid SPIRE server address {0:?}: {1}")]
    InvalidEndpoint(String, #[source] tonic::transport::Error),
    /// The TCP+TLS+HTTP2 handshake to the SPIRE server failed (unreachable,
    /// TLS rejected, timed out, ...).
    #[error("failed to connect to the SPIRE server at {0}: {1}")]
    Connect(String, #[source] tonic::transport::Error),
    /// A `ListEntries`/`BatchUpdateEntry` RPC returned a non-OK gRPC status.
    #[error("SPIRE Server Entry API call failed: {0}")]
    Grpc(#[from] tonic::Status),
}

/// Outcome of applying a new TTL across every registration entry found via
/// `ListEntries` pagination.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// Entries the server reported as successfully updated (status OK).
    pub updated: u32,
    /// Entries the server reported a non-OK `BatchUpdateEntry` status for.
    pub failed: u32,
}

/// Thin wrapper over the generated `Entry` service's gRPC client.
pub struct SpireEntryClient {
    inner: EntryClient<Channel>,
}

/// Splits `"host:port"` into just the host portion for TLS SNI — SPIRE
/// server addresses in this product are always a Kubernetes Service DNS
/// name (`spire-server.spire.svc:8081`-shaped), never a bracketed IPv6
/// literal, so a simple last-colon split is sufficient.
fn host_only(addr: &str) -> &str {
    addr.rsplit_once(':').map_or(addr, |(host, _)| host)
}

impl SpireEntryClient {
    /// Wraps an already-built `tonic::transport::Channel` — the seam this
    /// crate's own tests use (a plaintext in-process server), and available
    /// to any caller that builds its own channel.
    pub fn from_channel(channel: Channel) -> Self {
        Self {
            inner: EntryClient::new(channel),
        }
    }

    /// Connects to `server_addr` (`"host:port"`) over a manually-driven TLS
    /// handshake using `tls_config` (built by the caller, typically via
    /// `skauswatch_identity::IdentityProvider::client_tls_config`) — see
    /// the crate-level doc comment for why this doesn't use tonic's own TLS
    /// feature. `connect_timeout` bounds the whole TCP+TLS+HTTP2-negotiation
    /// handshake so an unreachable/black-holed SPIRE server fails fast
    /// rather than hanging the caller's request.
    ///
    /// # Errors
    /// See [`SpireEntryError`].
    pub async fn connect_mtls(
        server_addr: &str,
        tls_config: rustls::ClientConfig,
        connect_timeout: Duration,
    ) -> Result<Self, SpireEntryError> {
        let host = host_only(server_addr).to_owned();
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| SpireEntryError::InvalidServerName(server_addr.to_owned(), e))?;

        let tls_config = Arc::new(tls_config);
        let dial_addr = server_addr.to_owned();

        let connector = tower::service_fn(move |_uri: http::Uri| {
            let tls_config = Arc::clone(&tls_config);
            let dial_addr = dial_addr.clone();
            let server_name = server_name.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(&dial_addr).await?;
                let tls = tokio_rustls::TlsConnector::from(tls_config)
                    .connect(server_name, tcp)
                    .await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
            }
        });

        let endpoint = Endpoint::from_shared(format!("https://{server_addr}"))
            .map_err(|e| SpireEntryError::InvalidEndpoint(server_addr.to_owned(), e))?
            .connect_timeout(connect_timeout);
        let channel = endpoint
            .connect_with_connector(connector)
            .await
            .map_err(|e| SpireEntryError::Connect(server_addr.to_owned(), e))?;

        Ok(Self::from_channel(channel))
    }

    /// Applies `x509_ttl_seconds`/`jwt_ttl_seconds` to every registration
    /// entry in the trust domain: paginated `ListEntries` followed by a
    /// batched `BatchUpdateEntry` per page. SPIRE's Server API has no
    /// single "update every entry" call (colloquially referred to as
    /// `UpdateEntry` in this product's own docs — see
    /// `k8s/helm/spire/README.md#admin-adjustable-svid-ttl`), so this
    /// drives the same `list` -> `batch-update` sequence the
    /// `spire-server entry update` CLI itself performs per entry.
    ///
    /// # Errors
    /// The first `ListEntries`/`BatchUpdateEntry` transport/gRPC failure
    /// aborts the whole apply and is returned — callers should treat any
    /// `Err` here as "not yet applied" (see [`SpireEntryError`]), never as
    /// a reason to fail the request that already persisted the setting.
    pub async fn apply_svid_ttl(
        &mut self,
        x509_ttl_seconds: i32,
        jwt_ttl_seconds: i32,
    ) -> Result<ApplyOutcome, SpireEntryError> {
        let mut outcome = ApplyOutcome::default();
        let mut page_token = String::new();

        for _ in 0..MAX_LIST_PAGES {
            let list_resp = self
                .inner
                .list_entries(ListEntriesRequest {
                    page_size: 0,
                    page_token: page_token.clone(),
                })
                .await?
                .into_inner();

            if list_resp.entries.is_empty() {
                break;
            }

            let entries = list_resp
                .entries
                .iter()
                .map(|e| RegistrationEntry {
                    id: e.id.clone(),
                    x509_svid_ttl: x509_ttl_seconds,
                    jwt_svid_ttl: jwt_ttl_seconds,
                })
                .collect();
            let batch_resp = self
                .inner
                .batch_update_entry(BatchUpdateEntryRequest {
                    entries,
                    input_mask: Some(EntryMask {
                        x509_svid_ttl: true,
                        jwt_svid_ttl: true,
                    }),
                })
                .await?
                .into_inner();
            for result in batch_resp.results {
                let ok = result.status.as_ref().is_some_and(|s| s.code == 0);
                if ok {
                    outcome.updated += 1;
                } else {
                    outcome.failed += 1;
                }
            }

            if list_resp.next_page_token.is_empty() {
                break;
            }
            page_token = list_resp.next_page_token;
        }

        Ok(outcome)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status};

    use super::pb::entry_server::{Entry as EntryTrait, EntryServer};
    use super::pb::{
        BatchUpdateEntryRequest, BatchUpdateEntryResponse, ListEntriesRequest, ListEntriesResponse,
        RegistrationEntry, Status as PbStatus,
    };
    use super::*;

    #[test]
    fn host_only_strips_trailing_port() {
        assert_eq!(
            host_only("spire-server.spire.svc:8081"),
            "spire-server.spire.svc"
        );
        assert_eq!(host_only("no-port-host"), "no-port-host");
    }

    /// A fake `Entry` service holding a fixed page of entries and recording
    /// every `BatchUpdateEntry` request it receives, so tests can assert on
    /// exactly what was sent.
    struct FakeEntryService {
        /// Split into these many pages, in order — each `ListEntries` call
        /// (by page_token, 1-indexed as a string) returns the next page.
        pages: Vec<Vec<RegistrationEntry>>,
        /// Entries in this set get a non-OK `BatchUpdateEntry` status
        /// instead of OK.
        fail_ids: Vec<String>,
    }

    #[tonic::async_trait]
    impl EntryTrait for FakeEntryService {
        async fn list_entries(
            &self,
            request: Request<ListEntriesRequest>,
        ) -> Result<Response<ListEntriesResponse>, Status> {
            let token = request.into_inner().page_token;
            let index: usize = if token.is_empty() {
                0
            } else {
                token
                    .parse()
                    .map_err(|_| Status::invalid_argument("bad page_token"))?
            };
            let Some(entries) = self.pages.get(index) else {
                return Ok(Response::new(ListEntriesResponse {
                    entries: vec![],
                    next_page_token: String::new(),
                }));
            };
            let next_page_token = if index + 1 < self.pages.len() {
                (index + 1).to_string()
            } else {
                String::new()
            };
            Ok(Response::new(ListEntriesResponse {
                entries: entries.clone(),
                next_page_token,
            }))
        }

        async fn batch_update_entry(
            &self,
            request: Request<BatchUpdateEntryRequest>,
        ) -> Result<Response<BatchUpdateEntryResponse>, Status> {
            let req = request.into_inner();
            assert_eq!(
                req.input_mask,
                Some(EntryMask {
                    x509_svid_ttl: true,
                    jwt_svid_ttl: true,
                }),
                "apply_svid_ttl must request exactly the x509/jwt TTL fields"
            );
            let mut results = Vec::with_capacity(req.entries.len());
            for entry in &req.entries {
                let ok = !self.fail_ids.contains(&entry.id);
                results.push(pb::batch_update_entry_response::Result {
                    status: Some(PbStatus {
                        code: if ok { 0 } else { 3 }, // 3 == INVALID_ARGUMENT
                        message: if ok { String::new() } else { "boom".to_owned() },
                    }),
                    entry: ok.then(|| entry.clone()),
                });
            }
            Ok(Response::new(BatchUpdateEntryResponse { results }))
        }
    }

    fn entry(id: &str) -> RegistrationEntry {
        RegistrationEntry {
            id: id.to_owned(),
            x509_svid_ttl: 300,
            jwt_svid_ttl: 300,
        }
    }

    /// Spawns `service` on an ephemeral loopback port and returns a
    /// plaintext (no TLS) `SpireEntryClient` connected to it — this test
    /// module proves the `apply_svid_ttl` List+BatchUpdate logic; mTLS
    /// transport wiring itself is proven separately in
    /// `services/manager/src/grpc/spire_entry.rs`'s own tests (mirroring
    /// how `pki_client.rs`'s handshake test is separate from any RPC logic
    /// test).
    async fn spawn(service: FakeEntryService) -> SpireEntryClient {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral port");
        let addr: SocketAddr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(EntryServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });
        let channel = Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect");
        SpireEntryClient::from_channel(channel)
    }

    #[tokio::test]
    async fn apply_svid_ttl_updates_a_single_page_of_entries() {
        let service = FakeEntryService {
            pages: vec![vec![entry("entry-1"), entry("entry-2")]],
            fail_ids: vec![],
        };
        let mut client = spawn(service).await;

        let outcome = client
            .apply_svid_ttl(600, 900)
            .await
            .expect("apply_svid_ttl");
        assert_eq!(
            outcome,
            ApplyOutcome {
                updated: 2,
                failed: 0
            }
        );
    }

    #[tokio::test]
    async fn apply_svid_ttl_paginates_across_multiple_pages() {
        let service = FakeEntryService {
            pages: vec![
                vec![entry("entry-1")],
                vec![entry("entry-2"), entry("entry-3")],
            ],
            fail_ids: vec![],
        };
        let mut client = spawn(service).await;

        let outcome = client
            .apply_svid_ttl(600, 900)
            .await
            .expect("apply_svid_ttl");
        assert_eq!(
            outcome,
            ApplyOutcome {
                updated: 3,
                failed: 0
            }
        );
    }

    #[tokio::test]
    async fn apply_svid_ttl_counts_per_entry_failures_without_aborting() {
        let service = FakeEntryService {
            pages: vec![vec![entry("entry-ok"), entry("entry-bad")]],
            fail_ids: vec!["entry-bad".to_owned()],
        };
        let mut client = spawn(service).await;

        let outcome = client
            .apply_svid_ttl(600, 900)
            .await
            .expect("apply_svid_ttl");
        assert_eq!(
            outcome,
            ApplyOutcome {
                updated: 1,
                failed: 1
            }
        );
    }

    #[tokio::test]
    async fn apply_svid_ttl_no_entries_is_a_no_op_success() {
        let service = FakeEntryService {
            pages: vec![],
            fail_ids: vec![],
        };
        let mut client = spawn(service).await;

        let outcome = client
            .apply_svid_ttl(600, 900)
            .await
            .expect("apply_svid_ttl");
        assert_eq!(outcome, ApplyOutcome::default());
    }

    #[tokio::test]
    async fn apply_svid_ttl_sends_the_requested_ttls_on_every_entry() {
        let recorder = Arc::new(Mutex::new(Vec::<RegistrationEntry>::new()));
        let recorder_clone = Arc::clone(&recorder);

        struct RecordingService {
            inner: FakeEntryService,
            recorder: Arc<Mutex<Vec<RegistrationEntry>>>,
        }
        #[tonic::async_trait]
        impl EntryTrait for RecordingService {
            async fn list_entries(
                &self,
                request: Request<ListEntriesRequest>,
            ) -> Result<Response<ListEntriesResponse>, Status> {
                self.inner.list_entries(request).await
            }

            async fn batch_update_entry(
                &self,
                request: Request<BatchUpdateEntryRequest>,
            ) -> Result<Response<BatchUpdateEntryResponse>, Status> {
                self.recorder
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend(request.get_ref().entries.clone());
                self.inner.batch_update_entry(request).await
            }
        }

        let service = RecordingService {
            inner: FakeEntryService {
                pages: vec![vec![entry("entry-1")]],
                fail_ids: vec![],
            },
            recorder: recorder_clone,
        };
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(EntryServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });
        let channel = Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect");
        let mut client = SpireEntryClient::from_channel(channel);

        client
            .apply_svid_ttl(1234, 5678)
            .await
            .expect("apply_svid_ttl");

        let sent = recorder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].id, "entry-1");
        assert_eq!(sent[0].x509_svid_ttl, 1234);
        assert_eq!(sent[0].jwt_svid_ttl, 5678);
    }

    /// This workspace never relies on rustls's process-global default
    /// crypto provider (see `crates/skauswatch-identity/src/tls.rs`,
    /// exclusively `builder_with_provider`) — mirrored here.
    fn noop_verifier_tls_config() -> rustls::ClientConfig {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("safe default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoopVerifier))
            .with_no_client_auth()
    }

    #[tokio::test]
    async fn connect_mtls_rejects_invalid_hostname() {
        let tls_config = noop_verifier_tls_config();
        let result = SpireEntryClient::connect_mtls(
            "not a valid hostname:8081",
            tls_config,
            Duration::from_millis(200),
        )
        .await;
        assert!(matches!(
            result,
            Err(SpireEntryError::InvalidServerName(_, _))
        ));
    }

    /// Accepts any server certificate — this test only exercises the
    /// hostname-parsing and connect-failure paths, never a real handshake,
    /// so the verifier is never actually invoked; it exists purely to
    /// build a syntactically valid `rustls::ClientConfig` without pulling
    /// in a real certificate/root-store fixture.
    #[derive(Debug)]
    struct NoopVerifier;

    impl rustls::client::danger::ServerCertVerifier for NoopVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    #[tokio::test]
    async fn connect_mtls_fails_fast_on_unreachable_server() {
        let tls_config = noop_verifier_tls_config();
        // Port 0 on loopback is never a listening server — connection must
        // fail (fast, bounded by connect_timeout) rather than hang.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            SpireEntryClient::connect_mtls("127.0.0.1:0", tls_config, Duration::from_millis(500)),
        )
        .await
        .expect("connect_mtls must respect its own connect_timeout, not hang indefinitely");
        assert!(matches!(result, Err(SpireEntryError::Connect(_, _))));
    }
}
