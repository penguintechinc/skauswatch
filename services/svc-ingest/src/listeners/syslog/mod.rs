//! Syslog RFC 3164 + RFC 5424 listener: UDP (`SYSLOG_PORT`), plain TCP
//! (same port), and mTLS-authenticated TLS (`SYSLOG_TLS_PORT`) — see
//! `docs/v2-port/ingest-module-spec.md` §3b/§4a/§6/§7c. Every transport
//! resolves a tenant from the *authenticated* source (never the payload —
//! Spec §6d) before parsing and normalizing to OCSF via
//! [`skauswatch_ocsf::mappings::syslog::to_ocsf_fields`], then durably
//! buffers it through the shared [`crate::buffer::EventBuffer`].
//!
//! | Transport | Tenant source | Backpressure (buffer full, Spec §7c) |
//! |---|---|---|
//! | UDP | `SYSLOG_TRUSTED_CIDRS` (`crate::auth::resolve_via_udp_cidr`) | Drop packet (UDP has no feedback channel) |
//! | Plain TCP | Same trusted-CIDR config as UDP — plain TCP is equally unauthenticated and Spec §6c/Config expose no separate TCP-specific trust knob (documented reuse, not a bug); also gated by `SYSLOG_UDP_ENABLED` the same way UDP is, so the flag is a real "unauthenticated plain syslog off" switch rather than leaving a discoverable TCP port open | Close the connection; source reconnects and retries |
//! | TLS | mTLS peer certificate's SPIFFE ID (`crate::auth::resolve_via_mtls`) | Close the connection |

// `crate::listeners::syslog`'s `run_udp`/`run_tcp`/`run_tls` aren't wired
// into `main.rs`'s `serve()` until the Wave-1 integration gate (once Tasks
// 1.2/1.3's sibling listeners also land) — until then, `cargo build`'s
// reachability analysis (this crate has no `[lib]` target, only a
// `[[bin]]`) sees this whole module as unused. Same pattern as
// `crate::auth`/`crate::buffer`.
#![allow(dead_code)]

mod parser;

use std::sync::Arc;

use anyhow::Context as _;
use sha2::{Digest, Sha256};
use tokio::io::AsyncBufReadExt as _;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub use parser::{ParsedSyslog, detect_and_parse};

use crate::auth::AuthError;
use crate::buffer::{BufferError, EventBuffer, NormalizedEvent};
use crate::config::Config;
use crate::identity_store::IdentityStore;

/// SPIFFE trust domain every syslog-TLS mTLS peer must present. Mirrors
/// `crate::auth::EXPECTED_TRUST_DOMAIN`, which is private to that module —
/// duplicated here (rather than exposed, since editing `auth.rs` is out of
/// this task's file scope) per `penguintech.md`'s
/// `spiffe://penguintech.io/<env>/<service>` SPIFFE ID convention.
const SYSLOG_TLS_TRUST_DOMAIN: &str = "penguintech.io";

/// Deterministic content-hash `Nats-Msg-Id` dedup key for one normalized
/// event (Spec §7a/§7b: the key must be content-deterministic so a
/// client-side retry of the identical event is a server-side no-op on the
/// buffer, never a duplicate document). Reuses the `sha2` dependency
/// `crate::auth` already carries for ingest-token hashing.
fn dedup_key(tenant: &skauswatch_auth::Tenant, doc: &skauswatch_ocsf::JsonVal) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tenant.as_str().as_bytes());
    hasher.update(doc.to_compact_string().as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Normalizes `parsed` to OCSF, stamps it with the server-resolved
/// `tenant` (never a payload-derived one — Spec §6d), and durably buffers
/// it. Shared by all three transports below.
async fn enqueue(
    tenant: skauswatch_auth::Tenant,
    parsed: &ParsedSyslog,
    buffer: &dyn EventBuffer,
) -> Result<(), BufferError> {
    let record = skauswatch_ocsf::mappings::syslog::to_ocsf_fields(parsed);
    let doc = skauswatch_ocsf::normalize(&record, "syslog", chrono::Utc::now())
        .map_err(|e| BufferError::Serialize(e.to_string()))?;
    let dedup_key = dedup_key(&tenant, &doc);
    buffer
        .push(NormalizedEvent {
            tenant,
            doc,
            dedup_key,
        })
        .await
}

// -- UDP ---------------------------------------------------------------

/// Runs the syslog UDP listener until it errors or is aborted. A no-op
/// (returns immediately without binding a socket) when
/// `cfg.syslog_udp_enabled` is `false` — UDP syslog is OFF by default
/// (Spec §6c); an operator opts in via `SYSLOG_UDP_ENABLED=true` plus
/// `SYSLOG_TRUSTED_CIDRS`.
///
/// # Errors
/// Returns an error if the UDP socket fails to bind.
pub async fn run_udp(cfg: &Config, buffer: Arc<dyn EventBuffer>) -> anyhow::Result<()> {
    if !cfg.syslog_udp_enabled {
        tracing::info!("syslog UDP listener disabled (SYSLOG_UDP_ENABLED=false); not binding");
        return Ok(());
    }
    let socket = UdpSocket::bind(("0.0.0.0", cfg.syslog_port))
        .await
        .with_context(|| format!("bind syslog UDP :{}", cfg.syslog_port))?;
    tracing::info!(port = cfg.syslog_port, "syslog UDP listener bound");
    consume_udp(&socket, cfg, &buffer).await;
    Ok(())
}

/// Reads UDP datagrams from `socket` until it errors, resolving each
/// packet's tenant from its source IP (Spec §6c — UDP carries no
/// authentication of its own) before parsing and enqueueing it. A packet
/// from an untrusted source, or one that fails to parse, is silently
/// dropped — never an error, never a crash (Spec §6c/§14b). Extracted from
/// [`run_udp`] as a test seam (mirrors
/// `services/monitor/src/collectors/syslog.rs::consume_socket`).
pub(crate) async fn consume_udp(socket: &UdpSocket, cfg: &Config, buffer: &Arc<dyn EventBuffer>) {
    let mut buf = [0u8; 65535];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "syslog UDP recv failed");
                return;
            }
        };
        let Some(tenant) = crate::auth::resolve_via_udp_cidr(peer.ip(), cfg) else {
            // Untrusted source (or UDP disabled) — silently dropped, no
            // error: UDP has no feedback channel (Spec §6c/§14b).
            continue;
        };
        let raw = String::from_utf8_lossy(&buf[..len]);
        let Some(parsed) = detect_and_parse(&raw) else {
            // Malformed datagram — dropped, never crashes the listener
            // (Spec §14a).
            continue;
        };
        if let Err(e) = enqueue(tenant, &parsed, buffer.as_ref()).await {
            tracing::error!(error = %e, "syslog UDP event buffer push failed");
        }
    }
}

// -- Plain TCP -----------------------------------------------------------

/// Runs the syslog TCP listener until it errors or is aborted. Shares
/// `cfg.syslog_port` with [`run_udp`] (Spec §3b) — see this module's
/// top-level doc table for why plain (non-TLS) TCP reuses UDP's
/// trusted-CIDR tenant resolution. Gated by the same
/// `cfg.syslog_udp_enabled` flag as [`run_udp`] (a no-op, no bind, when
/// `false`): plain TCP is exactly as unauthenticated as UDP, so an
/// operator using the flag as "unauthenticated plain-syslog off" must not
/// still find a listening, discoverable `:syslog_port` TCP socket — only
/// [`run_tls`] (mTLS-authenticated) stays always-on regardless of this
/// flag.
///
/// # Errors
/// Returns an error if the TCP listener fails to bind.
pub async fn run_tcp(cfg: &Config, buffer: Arc<dyn EventBuffer>) -> anyhow::Result<()> {
    if !cfg.syslog_udp_enabled {
        tracing::info!(
            "syslog plain-TCP listener disabled (SYSLOG_UDP_ENABLED=false); not binding"
        );
        return Ok(());
    }
    let listener = TcpListener::bind(("0.0.0.0", cfg.syslog_port))
        .await
        .with_context(|| format!("bind syslog TCP :{}", cfg.syslog_port))?;
    tracing::info!(port = cfg.syslog_port, "syslog TCP listener bound");
    serve_tcp(listener, cfg, buffer).await;
    Ok(())
}

/// Accepts connections from `listener` until `accept` errors, resolving
/// each peer's tenant from its source IP before spawning a per-connection
/// handler. Extracted from [`run_tcp`] as a test seam: tests bind their
/// own ephemeral-port `TcpListener` (so they can learn and connect to its
/// address) instead of `run_tcp`'s fixed `cfg.syslog_port`.
pub(crate) async fn serve_tcp(listener: TcpListener, cfg: &Config, buffer: Arc<dyn EventBuffer>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "syslog TCP accept failed");
                continue;
            }
        };
        let Some(tenant) = crate::auth::resolve_via_udp_cidr(peer.ip(), cfg) else {
            tracing::warn!(%peer, "syslog TCP connection from untrusted source, refusing");
            continue;
        };
        let buffer = Arc::clone(&buffer);
        tokio::spawn(async move {
            handle_tcp_connection(stream, tenant, buffer).await;
        });
    }
}

/// Reads newline-delimited syslog lines from `stream` until the peer
/// closes it, a read fails, or the event buffer signals backpressure.
/// Extracted from [`serve_tcp`] as a test seam; the actual read/parse/
/// enqueue loop lives in [`read_and_enqueue_lines`], shared with
/// [`handle_tls_connection`].
pub(crate) async fn handle_tcp_connection(
    stream: TcpStream,
    tenant: skauswatch_auth::Tenant,
    buffer: Arc<dyn EventBuffer>,
) {
    read_and_enqueue_lines(tokio::io::BufReader::new(stream), tenant, buffer, "tcp").await;
}

/// Reads newline-delimited syslog lines from `reader` until the peer
/// closes it, a read fails, or the event buffer signals backpressure — per
/// Spec §7c, a full buffer on a connection-oriented transport (TCP or TLS)
/// is handled by closing the connection (returning, which drops `reader`),
/// never by blocking or silently dropping messages: the source must
/// reconnect and retry. A line that fails to parse is dropped and the
/// connection stays open (Spec §14a "malformed" vectors are a parse
/// concern, not a transport-level failure). Shared by
/// [`handle_tcp_connection`] and [`handle_tls_connection`] — generic over
/// the reader so both a plain `TcpStream` and a `tokio_rustls` `TlsStream`
/// (and, in tests, an in-memory duplex pipe) all drive the exact same
/// logic. `transport` is a `tracing` label only (`"tcp"`/`"tls"`).
async fn read_and_enqueue_lines<R>(
    reader: R,
    tenant: skauswatch_auth::Tenant,
    buffer: Arc<dyn EventBuffer>,
    transport: &str,
) where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut lines = reader.lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, transport, "syslog read failed");
                return;
            }
        };
        let Some(parsed) = detect_and_parse(&line) else {
            continue;
        };
        match enqueue(tenant.clone(), &parsed, buffer.as_ref()).await {
            Ok(()) => {}
            Err(BufferError::Full) => {
                tracing::warn!(
                    transport,
                    "syslog backpressure: event buffer full, closing connection"
                );
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, transport, "syslog event buffer push failed");
                return;
            }
        }
    }
}

// -- TLS (mTLS) ------------------------------------------------------------

/// Builds the [`SpiffeIdMatcher`](skauswatch_identity::SpiffeIdMatcher)
/// every syslog-TLS mTLS peer's certificate must satisfy — any SPIFFE ID
/// in [`SYSLOG_TLS_TRUST_DOMAIN`]. Pure and infallible in practice (the
/// only error path is a malformed [`SYSLOG_TLS_TRUST_DOMAIN`] constant,
/// which is under this module's own control) — factored out of
/// [`run_tls`] so it's testable without a live SPIFFE Workload API.
fn tls_allowed_matcher() -> anyhow::Result<skauswatch_identity::SpiffeIdMatcher> {
    let trust_domain = skauswatch_identity::TrustDomain::new(SYSLOG_TLS_TRUST_DOMAIN)
        .map_err(|e| anyhow::anyhow!("syslog TLS trust domain: {e}"))?;
    Ok(skauswatch_identity::SpiffeIdMatcher::new().allow_trust_domain(trust_domain))
}

/// Runs the syslog-over-TLS listener until it errors or is aborted.
/// Requires mTLS (Spec §6a): connects to the local SPIFFE Workload API for
/// this workload's own identity, builds a mTLS server config trusting any
/// peer in [`SYSLOG_TLS_TRUST_DOMAIN`], and resolves each connection's
/// tenant from its peer certificate's SPIFFE ID via
/// [`crate::auth::resolve_via_mtls`].
///
/// # Degrades, never hard-fails, when no SPIFFE identity is available
///
/// Unlike [`crate::listeners::otlp::run_grpc`] (which receives an
/// already-connected `Option<Arc<IdentityProvider>>` from `main.rs`'s
/// once-per-process Wave-1 wiring), this listener still attests to the
/// Workload API itself — see that module's doc comment for why re-deriving
/// identity per listener is a documented gap, not a design goal. Applying
/// `skauswatch_identity`'s own hard-fail-in-production policy at *this*
/// call site would crash the whole receiver (`/ingest` included) over one
/// listener's transport concern, cascading through
/// `bootstrap::drain_listeners`'s "any listener errors, shut every listener
/// down" behavior. So both ways an identity can be unavailable —
/// `IdentityProvider::connect` itself failing, or connecting but holding no
/// attested identity (`has_identity() == false`, the crate's own
/// non-production degrade case) — are treated identically here: log a
/// `tracing::warn!` and return `Ok(())` without ever binding
/// `cfg.syslog_tls_port`. The receiver stays up with `:6514` simply
/// unavailable, mirroring `run_grpc`'s plaintext-fallback precedent (this
/// listener has no plaintext equivalent to fall back to, since mTLS *is*
/// its authentication mechanism, so "disabled" is the only safe fallback).
///
/// # Errors
/// Returns an error if the mTLS server config cannot be built despite a
/// held identity (a genuine bug, e.g. an empty trust bundle), the
/// identity-store database is unreachable, or the TCP listener fails to
/// bind.
pub async fn run_tls(cfg: &Config, buffer: Arc<dyn EventBuffer>) -> anyhow::Result<()> {
    let identity = match skauswatch_identity::IdentityProvider::connect().await {
        Ok(identity) => identity,
        Err(e) => {
            tracing::warn!(
                error = %e,
                port = cfg.syslog_tls_port,
                "syslog TLS listener degraded: could not attest to the SPIFFE Workload API; \
                 not binding the TLS port"
            );
            return Ok(());
        }
    };
    if !identity.has_identity() {
        tracing::warn!(
            port = cfg.syslog_tls_port,
            "syslog TLS listener degraded: no SPIFFE workload identity held; not binding the \
             TLS port"
        );
        return Ok(());
    }
    let allowed = tls_allowed_matcher()?;
    let tls_config = identity
        .server_tls_config(&allowed)
        .context("build syslog TLS mTLS server config")?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let store = Arc::new(build_identity_store().await?);

    let listener = TcpListener::bind(("0.0.0.0", cfg.syslog_tls_port))
        .await
        .with_context(|| format!("bind syslog TLS :{}", cfg.syslog_tls_port))?;
    tracing::info!(port = cfg.syslog_tls_port, "syslog TLS listener bound");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "syslog TLS accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let store = Arc::clone(&store);
        let buffer = Arc::clone(&buffer);
        tokio::spawn(async move {
            handle_tls_connection(stream, acceptor, store, buffer).await;
        });
    }
}

/// Builds the [`IdentityStore`] [`run_tls`] resolves mTLS peers' tenants
/// against, connecting to the database named by the standard
/// `skauswatch_db::DbConfig` environment variables. Schema is applied
/// separately via the `migrate` subcommand — this constructor never
/// migrates.
async fn build_identity_store() -> anyhow::Result<IdentityStore> {
    let db_cfg =
        skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
    let pool = skauswatch_db::connect_postgres(&db_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;
    Ok(IdentityStore::new(pool))
}

/// Completes a mTLS handshake on `stream`, resolves the peer's tenant, and
/// (on success) reads newline-delimited syslog lines the same way
/// [`handle_tcp_connection`] does. A failed handshake never reaches an
/// application-level `SpiffeId` at all — `acceptor.accept` itself fails —
/// which is this call site's carry-forward of Task 1.4's documented
/// [`AuthError::InvalidCert`]: `crate::auth`'s
/// `mtls_cert_invalid_is_rejected_403` test names exactly this — "the 403
/// mapping ... is the value a listener (Task 1.1-1.3) returns directly
/// when certificate parsing/handshake verification fails, without ever
/// calling [`crate::auth::resolve_via_mtls`]".
async fn handle_tls_connection(
    stream: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    store: Arc<IdentityStore>,
    buffer: Arc<dyn EventBuffer>,
) {
    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error = %e,
                mapped_status = ?AuthError::InvalidCert.status_code(),
                "syslog TLS handshake failed"
            );
            return;
        }
    };

    let peer_certs = tls_stream.get_ref().1.peer_certificates();
    let tenant = match resolve_tls_tenant(peer_certs, &store).await {
        Ok(tenant) => tenant,
        Err(e) => {
            tracing::warn!(error = %e, "syslog TLS peer tenant resolution failed");
            return;
        }
    };

    read_and_enqueue_lines(tokio::io::BufReader::new(tls_stream), tenant, buffer, "tls").await;
}

/// Resolves an already-completed mTLS handshake's peer certificate chain
/// to its provisioned tenant — factored out of [`handle_tls_connection`]
/// so the certificate-shape checks are testable without a live TLS
/// handshake. A missing or empty certificate chain is
/// [`AuthError::InvalidCert`] (defense-in-depth only:
/// `IdentityProvider::server_tls_config`'s `ClientCertVerifier` already
/// makes client-cert presentation mandatory, so `acceptor.accept` itself
/// would already have failed the handshake before this function is ever
/// reached in practice).
async fn resolve_tls_tenant(
    peer_certs: Option<&[rustls::pki_types::CertificateDer<'static>]>,
    store: &IdentityStore,
) -> Result<skauswatch_auth::Tenant, AuthError> {
    let certs = peer_certs.ok_or(AuthError::InvalidCert)?;
    let leaf = certs.first().ok_or(AuthError::InvalidCert)?;
    let spiffe_id =
        spiffe::cert::spiffe_id_from_der(leaf.as_ref()).map_err(|_err| AuthError::InvalidCert)?;
    crate::auth::resolve_via_mtls(&spiffe_id, store).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    use super::*;
    use crate::buffer::{AckHandle, DeliveredEvent, InMemoryBuffer};
    use crate::config::CidrBlock;

    /// Builds a `Config` fixture via its public fields directly, same
    /// approach `crate::auth`'s own test module uses (`Config`'s
    /// constructors are private to the `config` module).
    fn test_config(udp_enabled: bool, cidrs: Vec<CidrBlock>, tenant: Option<&str>) -> Config {
        Config {
            http_port: 8443,
            syslog_port: 5140,
            syslog_tls_port: 6514,
            otlp_grpc_port: 4317,
            otlp_http_port: 4318,
            opensearch_url: "http://localhost:9200".to_owned(),
            nats_url: "nats://localhost:4222".to_owned(),
            nats_jetstream_subject_prefix: "svc-ingest.logs".to_owned(),
            syslog_udp_enabled: udp_enabled,
            syslog_trusted_cidrs: cidrs,
            syslog_udp_tenant_id: tenant.map(str::to_owned),
        }
    }

    fn ipv4_cidr(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) -> CidrBlock {
        CidrBlock {
            network: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            prefix_len,
        }
    }

    /// Loopback-trusting config: every test in this module talks over
    /// `127.0.0.1`, so the trusted CIDR must actually include it whenever
    /// a test wants the CIDR check to pass.
    fn loopback_trusting_config() -> Config {
        test_config(true, vec![ipv4_cidr(127, 0, 0, 0, 8)], Some("tenant-udp"))
    }

    /// Untrusted config: UDP/TCP enabled, but the only trusted CIDR is a
    /// range that never includes the loopback address every test connects
    /// from — used to exercise the "silently dropped" / "refused" paths.
    fn untrusted_config() -> Config {
        test_config(true, vec![ipv4_cidr(10, 0, 0, 0, 8)], Some("tenant-udp"))
    }

    /// `EventBuffer` test double that only counts `push` calls (always
    /// succeeding) — lets a test assert "the listener never reached the
    /// buffer" precisely, which `InMemoryBuffer` (test-only fallback,
    /// reused below for the backpressure and content-shape tests) doesn't
    /// expose a call counter for.
    #[derive(Default)]
    struct PushCountingBuffer {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl EventBuffer for PushCountingBuffer {
        async fn push(&self, _event: NormalizedEvent) -> Result<(), BufferError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn consume(&self, _batch_size: usize) -> Result<Vec<DeliveredEvent>, BufferError> {
            Ok(Vec::new())
        }

        async fn ack(&self, _handle: AckHandle) -> Result<(), BufferError> {
            Ok(())
        }

        async fn nack(&self, _handle: AckHandle) -> Result<(), BufferError> {
            Ok(())
        }
    }

    /// `EventBuffer` test double whose `push` always fails with a
    /// non-`Full` transport error — distinguishes
    /// `read_and_enqueue_lines`'s generic-error-closes branch from its
    /// `BufferError::Full`-closes branch (`InMemoryBuffer` only ever
    /// produces the latter).
    #[derive(Default)]
    struct AlwaysTransportErrorBuffer;

    #[async_trait::async_trait]
    impl EventBuffer for AlwaysTransportErrorBuffer {
        async fn push(&self, _event: NormalizedEvent) -> Result<(), BufferError> {
            Err(BufferError::Transport(
                "simulated transport failure".to_owned(),
            ))
        }

        async fn consume(&self, _batch_size: usize) -> Result<Vec<DeliveredEvent>, BufferError> {
            Ok(Vec::new())
        }

        async fn ack(&self, _handle: AckHandle) -> Result<(), BufferError> {
            Ok(())
        }

        async fn nack(&self, _handle: AckHandle) -> Result<(), BufferError> {
            Ok(())
        }
    }

    // -- consume_udp -------------------------------------------------------

    #[tokio::test]
    async fn udp_packet_from_untrusted_cidr_is_silently_dropped_no_error() {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = socket
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let cfg = untrusted_config();
        let counting = Arc::new(PushCountingBuffer::default());
        let erased: Arc<dyn EventBuffer> = counting.clone();

        let consumer = tokio::spawn(async move {
            consume_udp(&socket, &cfg, &erased).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind client: {e}"));
        client
            .send_to(b"<34>Oct 11 22:14:15 host msg", addr)
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));

        // UDP has no feedback channel to await — give the consumer task a
        // moment to (not) act on the datagram, then assert it never
        // reached `EventBuffer::push`.
        tokio::time::sleep(Duration::from_millis(200)).await;
        consumer.abort();
        assert_eq!(
            counting.calls.load(Ordering::SeqCst),
            0,
            "a packet from an untrusted CIDR must never reach EventBuffer::push"
        );
    }

    #[tokio::test]
    async fn malformed_datagram_does_not_crash_the_listener() {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = socket
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let cfg = loopback_trusting_config();
        let counting = Arc::new(PushCountingBuffer::default());
        let erased: Arc<dyn EventBuffer> = counting.clone();

        let consumer = tokio::spawn(async move {
            consume_udp(&socket, &cfg, &erased).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind client: {e}"));
        client
            .send_to(b"not a syslog message", addr)
            .await
            .unwrap_or_else(|e| panic!("send malformed: {e}"));
        client
            .send_to(
                b"<38>Oct 11 22:14:15 host1 sshd: Failed password for root",
                addr,
            )
            .await
            .unwrap_or_else(|e| panic!("send well-formed: {e}"));

        // Poll briefly instead of a single fixed sleep: the listener task
        // must still be alive and processing after the malformed datagram
        // (that's the property under test), not merely "eventually
        // consistent" some fixed delay later.
        for _ in 0..50 {
            if counting.calls.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            counting.calls.load(Ordering::SeqCst),
            1,
            "the malformed datagram must be dropped, not crash the listener, and the well-formed one that followed must still be pushed"
        );
        consumer.abort();
    }

    #[tokio::test]
    async fn udp_packet_from_trusted_cidr_is_pushed_with_stamped_tenant() {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = socket
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let cfg = loopback_trusting_config();
        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        let buffer_clone = Arc::clone(&buffer);

        let consumer = tokio::spawn(async move {
            consume_udp(&socket, &cfg, &buffer_clone).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind client: {e}"));
        client
            .send_to(b"<34>Oct 11 22:14:15 host msg", addr)
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));

        let mut delivered = Vec::new();
        for _ in 0..50 {
            delivered = buffer.consume(10).await.unwrap_or_else(|e| panic!("{e}"));
            if !delivered.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        consumer.abort();

        assert_eq!(delivered.len(), 1);
        assert_eq!(
            delivered[0].event.tenant,
            skauswatch_auth::Tenant("tenant-udp".to_owned())
        );
        assert_eq!(
            delivered[0]
                .event
                .doc
                .get("message")
                .and_then(|v| v.as_str()),
            Some("msg")
        );
        assert!(!delivered[0].event.dedup_key.is_empty());
    }

    #[tokio::test]
    async fn udp_packet_enqueue_failure_is_logged_and_listener_keeps_running() {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = socket
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let cfg = loopback_trusting_config();
        // Zero-capacity buffer: every push fails, exercising `consume_udp`'s
        // "enqueue failed, log and keep serving" branch (never crash, never
        // stop the listener) rather than its happy path.
        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(0));

        let consumer = tokio::spawn(async move {
            consume_udp(&socket, &cfg, &buffer).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind client: {e}"));
        client
            .send_to(b"<34>Oct 11 22:14:15 host msg", addr)
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !consumer.is_finished(),
            "a failed enqueue must be logged, not crash or stop the UDP listener"
        );
        consumer.abort();
    }

    // -- run_udp -------------------------------------------------------------

    #[tokio::test]
    async fn run_udp_disabled_returns_ok_without_binding() {
        let cfg = test_config(false, vec![], None);
        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(1));
        run_udp(&cfg, buffer)
            .await
            .unwrap_or_else(|e| panic!("disabled run_udp must return Ok: {e}"));
    }

    #[tokio::test]
    async fn run_udp_enabled_binds_and_delegates_to_consume_udp() {
        let mut cfg = loopback_trusting_config();
        cfg.syslog_port = 0; // OS-assigned ephemeral port — no fixed-port collision risk.
        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(1));
        // `run_udp` never returns once bound (it hands off to `consume_udp`'s
        // infinite loop) — proving it got past the bind and into that loop
        // without panicking is the property under test here; `consume_udp`
        // itself already has its own direct, fully-asserted coverage above.
        let task = tokio::spawn(async move { run_udp(&cfg, buffer).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !task.is_finished(),
            "run_udp should still be serving, not have errored out"
        );
        task.abort();
    }

    // -- serve_tcp / handle_tcp_connection ---------------------------------

    #[tokio::test]
    async fn tcp_backpressure_closes_connection_on_buffer_full() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));

        // Zero-capacity `InMemoryBuffer` always returns `BufferError::Full`
        // — the "mock buffer" the acceptance criteria calls for, reusing
        // the fixture `crate::buffer` already provides and tests
        // elsewhere rely on for exactly this behavior.
        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(0));
        let tenant = skauswatch_auth::Tenant("tenant-a".to_owned());

        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|e| panic!("accept: {e}"));
            handle_tcp_connection(stream, tenant, buffer).await;
        });

        let mut client = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        client
            .write_all(b"<34>Oct 11 22:14:15 host msg\n")
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));

        // The server side must close the connection once the
        // always-`Full` buffer rejects the push — the client observes
        // this as EOF (a 0-byte read), never a hang.
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("expected the connection to close, not hang"))
            .unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(
            n, 0,
            "expected EOF once the server closes the backpressured connection"
        );

        server
            .await
            .unwrap_or_else(|e| panic!("server task join: {e}"));
    }

    #[tokio::test]
    async fn tcp_connection_stays_open_and_pushes_each_well_formed_line() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let counting = Arc::new(PushCountingBuffer::default());
        let erased: Arc<dyn EventBuffer> = counting.clone();
        let tenant = skauswatch_auth::Tenant("tenant-a".to_owned());

        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|e| panic!("accept: {e}"));
            handle_tcp_connection(stream, tenant, erased).await;
        });

        let mut client = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        client
            .write_all(b"<34>Oct 11 22:14:15 host msg-one\nnot a syslog line\n<34>Oct 11 22:14:16 host msg-two\n")
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        drop(client);

        server
            .await
            .unwrap_or_else(|e| panic!("server task join: {e}"));
        assert_eq!(
            counting.calls.load(Ordering::SeqCst),
            2,
            "both well-formed lines must be pushed; the malformed one in between must be dropped, not close the connection"
        );
    }

    #[tokio::test]
    async fn tcp_connection_from_trusted_source_is_handled_via_serve_tcp() {
        // Exercises `serve_tcp`'s own happy-path wiring end to end (accept
        // -> resolve tenant -> clone buffer -> spawn -> delegate to
        // `handle_tcp_connection`) rather than calling
        // `handle_tcp_connection` directly, as the tests above do.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let cfg = loopback_trusting_config();
        let counting = Arc::new(PushCountingBuffer::default());
        let erased: Arc<dyn EventBuffer> = counting.clone();

        let server = tokio::spawn(async move {
            serve_tcp(listener, &cfg, erased).await;
        });

        let mut client = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        client
            .write_all(b"<34>Oct 11 22:14:15 host msg\n")
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        drop(client);

        for _ in 0..50 {
            if counting.calls.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(counting.calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn tcp_connection_from_untrusted_source_is_refused_without_reading() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let cfg = untrusted_config();
        let counting = Arc::new(PushCountingBuffer::default());
        let erased: Arc<dyn EventBuffer> = counting.clone();

        let server = tokio::spawn(async move {
            serve_tcp(listener, &cfg, erased).await;
        });

        let mut client = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        // The server refuses without ever reading — asserted indirectly:
        // the connection closes (EOF) without any push ever happening.
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("expected the untrusted connection to close"))
            .unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(n, 0);
        assert_eq!(counting.calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn run_tcp_binds_and_delegates_to_serve_tcp() {
        let mut cfg = untrusted_config();
        cfg.syslog_port = 0; // OS-assigned ephemeral port.
        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(1));
        let task = tokio::spawn(async move { run_tcp(&cfg, buffer).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !task.is_finished(),
            "run_tcp should still be serving, not have errored out"
        );
        task.abort();
    }

    #[tokio::test]
    async fn run_tcp_disabled_returns_ok_without_binding() {
        let cfg = test_config(false, vec![], None);
        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(1));
        run_tcp(&cfg, buffer)
            .await
            .unwrap_or_else(|e| panic!("disabled run_tcp must return Ok: {e}"));
    }

    // -- read_and_enqueue_lines (direct, transport-agnostic) ------------------

    #[tokio::test]
    async fn read_and_enqueue_lines_closes_on_buffer_full_over_a_duplex_pipe() {
        let (mut client, server) = tokio::io::duplex(4096);
        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(0));
        let tenant = skauswatch_auth::Tenant("tenant-a".to_owned());

        let task = tokio::spawn(async move {
            read_and_enqueue_lines(tokio::io::BufReader::new(server), tenant, buffer, "test").await;
        });

        client
            .write_all(b"<34>Oct 11 22:14:15 host msg\n")
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("expected the pipe to close on backpressure"))
            .unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(n, 0);
        task.await.unwrap_or_else(|e| panic!("task join: {e}"));
    }

    #[tokio::test]
    async fn read_and_enqueue_lines_drops_malformed_lines_and_keeps_reading() {
        let (mut client, server) = tokio::io::duplex(4096);
        let counting = Arc::new(PushCountingBuffer::default());
        let erased: Arc<dyn EventBuffer> = counting.clone();
        let tenant = skauswatch_auth::Tenant("tenant-a".to_owned());

        let task = tokio::spawn(async move {
            read_and_enqueue_lines(tokio::io::BufReader::new(server), tenant, erased, "test").await;
        });

        client
            .write_all(b"garbage\n<34>Oct 11 22:14:15 host msg\n")
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        drop(client);

        task.await.unwrap_or_else(|e| panic!("task join: {e}"));
        assert_eq!(counting.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn read_and_enqueue_lines_closes_on_a_non_full_buffer_error_too() {
        let (mut client, server) = tokio::io::duplex(4096);
        let buffer: Arc<dyn EventBuffer> = Arc::new(AlwaysTransportErrorBuffer);
        let tenant = skauswatch_auth::Tenant("tenant-a".to_owned());

        let task = tokio::spawn(async move {
            read_and_enqueue_lines(tokio::io::BufReader::new(server), tenant, buffer, "test").await;
        });

        client
            .write_all(b"<34>Oct 11 22:14:15 host msg\n")
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("expected the pipe to close on a transport error"))
            .unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(n, 0);
        task.await.unwrap_or_else(|e| panic!("task join: {e}"));
    }

    // -- resolve_tls_tenant --------------------------------------------------

    /// A lazily-connected pool never performs I/O until first queried —
    /// safe to use here since every case below short-circuits with
    /// `AuthError::InvalidCert` before `resolve_via_mtls` would ever touch
    /// the store, so no real Postgres connection is required for these
    /// specific (certificate-shape) branches.
    fn lazy_store() -> IdentityStore {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@localhost:1/unused")
            .unwrap_or_else(|e| panic!("connect_lazy is infallible for a well-formed URL: {e}"));
        IdentityStore::new(pool)
    }

    #[tokio::test]
    async fn tls_no_peer_certificate_is_invalid_cert() {
        let store = lazy_store();
        let err = resolve_tls_tenant(None, &store)
            .await
            .expect_err("no certificate must be rejected");
        assert_eq!(err, AuthError::InvalidCert);
    }

    #[tokio::test]
    async fn tls_empty_certificate_chain_is_invalid_cert() {
        let store = lazy_store();
        let err = resolve_tls_tenant(Some(&[]), &store)
            .await
            .expect_err("an empty chain must be rejected");
        assert_eq!(err, AuthError::InvalidCert);
    }

    #[tokio::test]
    async fn tls_certificate_with_no_valid_spiffe_id_is_invalid_cert() {
        let store = lazy_store();
        // Not a real X.509 certificate — `spiffe_id_from_der` must reject
        // this as unparsable rather than panicking, mapped to
        // `AuthError::InvalidCert` same as a missing/empty chain.
        let bogus = rustls::pki_types::CertificateDer::from(vec![0u8; 8]);
        let err = resolve_tls_tenant(Some(std::slice::from_ref(&bogus)), &store)
            .await
            .expect_err("an unparsable certificate must be rejected");
        assert_eq!(err, AuthError::InvalidCert);
    }

    // -- tls_allowed_matcher --------------------------------------------------

    #[test]
    fn tls_allowed_matcher_admits_the_configured_trust_domain() {
        let allowed = tls_allowed_matcher().unwrap_or_else(|e| panic!("{e}"));
        let id = spiffe::SpiffeId::new("spiffe://penguintech.io/prod/some-agent")
            .unwrap_or_else(|e| panic!("valid test SPIFFE id: {e}"));
        assert!(allowed.matches(&id));
    }

    #[test]
    fn tls_allowed_matcher_rejects_a_different_trust_domain() {
        let allowed = tls_allowed_matcher().unwrap_or_else(|e| panic!("{e}"));
        let id = spiffe::SpiffeId::new("spiffe://evil.example.com/prod/some-agent")
            .unwrap_or_else(|e| panic!("valid test SPIFFE id: {e}"));
        assert!(!allowed.matches(&id));
    }

    // -- run_tls ---------------------------------------------------------------

    // regression: e2e harness finding -- a receiver with no live SPIRE
    // agent must stay up with `:6514` simply disabled, not crash the whole
    // process (`bootstrap::drain_listeners` shuts every listener down on
    // the first `Err`). `run_tls` must degrade (`Ok(())`, never binding the
    // TLS port) whenever a SPIFFE identity can't be obtained, exactly
    // mirroring `otlp::run_grpc`'s warn-and-degrade precedent.
    #[tokio::test]
    async fn run_tls_degrades_to_ok_without_binding_when_no_live_spiffe_workload_api() {
        // No SPIRE agent runs in this test environment and
        // `SPIFFE_ENDPOINT_SOCKET` is unset, so `IdentityProvider::connect`
        // fails fast (no network I/O attempted, matches
        // `skauswatch-identity`'s own
        // `connect_fails_deterministically_without_a_live_workload_api_socket`
        // regression) -- `run_tls` must treat that as a degrade, not
        // propagate it as an `Err` that would cascade into shutting the
        // whole receiver down.
        let mut cfg = untrusted_config();
        cfg.syslog_tls_port = 0; // never actually bound on the degrade path
        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(1));
        let result = run_tls(&cfg, buffer).await;
        assert!(
            result.is_ok(),
            "run_tls must degrade (Ok, TLS port left unbound), never hard-fail the receiver \
             over a missing SPIFFE Workload API: {result:?}"
        );
    }
}
