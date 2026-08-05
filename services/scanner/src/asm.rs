//! ASM (Attack Surface Management) pipeline: `masscan` port discovery →
//! banner grab → TLS certificate inspection → diff against the previous
//! completed scan for the same target. Invoked by `handler.rs` for
//! `scan_type: "asm"` stream tasks; writes results directly into the
//! `asm_*` tables — owned by `services/manager`'s migrations
//! (`0006_asm_schema.sql`), not this crate's — the same cross-service
//! table-ownership split already established between `manager` and
//! `s3scan` (see that migration's module doc). This worker has no local
//! migration for these tables; its own test suite layers manager's
//! migrations in via `skauswatch_testkit::db::test_pool_multi` (see the
//! `tests` module below).
//!
//! **Screenshot capture** (this pass): for each discovered HTTP(S) service
//! ([`HTTP_PORTS`]) a headless `chromium` subprocess renders the page and
//! writes a PNG (`capture_screenshot`); the bytes upload to S3/MinIO via
//! [`ScreenshotUploader`] (built on `crates/skauswatch-s3`'s standard
//! AWS-provider-chain client — this is an internal artifact bucket, not a
//! customer-owned one, so it does not need `skauswatch_s3::credentials`'
//! per-tenant STS/envelope-key resolution) and a row lands in
//! `asm_screenshots`, tenant-stamped and keyed
//! `asm/{tenant_id}/{scan_id}/{service_id}.png`. **v1's `xfreerdp`/
//! `vncsnapshot` stages for RDP/VNC (ports 3389/5900) are intentionally
//! out of scope here** — the task scope is HTTP(S) only; those two
//! protocols stay unimplemented (no `asm_screenshots` rows for them),
//! consistent with the "don't build unreachable/out-of-scope code" posture
//! already applied to nuclei/zap/openvas below.
//!
//! Screenshot capture is **fail-safe per host**: a `chromium` spawn/exit/
//! timeout failure, or an S3 upload failure, is logged and the pipeline
//! moves on to the next service — it never fails the enclosing scan (which
//! is already fully useful from masscan/banner/cert alone). The stage is
//! entirely optional at the pipeline level too: `AsmPipelineConfig.
//! screenshot` is `None` whenever `ASM_SCREENSHOT_ENABLED=false` or
//! `ASM_SCREENSHOT_BUCKET` is unset (see `crate::config::WorkerConfig`),
//! in which case no screenshot is attempted and `asm_screenshots` simply
//! stays empty for that scan — the same graceful-skip behavior this file
//! had before this stage existed.
//!
//! **Container/runtime requirement, flagged not silently assumed**: this
//! stage requires a `chromium` (or `chromium-browser`) binary in the
//! scanner image — not present in `services/scanner/Dockerfile` as of this
//! change, and not yet installed by any Helm chart. Headless Chromium
//! launches its own sandboxed renderer process tree; under this workspace's
//! rootless-by-default `securityContext` (`capabilities.drop: [ALL]`,
//! non-root UID, no `CAP_SYS_ADMIN`) Chromium's own setuid sandbox cannot
//! initialize, so this code invokes it with `--no-sandbox` — a deliberate,
//! narrower trade-off than granting a Linux capability: the *contained*
//! renderer process (which parses attacker-influenced, scan-discovered web
//! content) loses its own internal sandbox layer, but the outer container
//! boundary (non-root, dropped capabilities, read-only rootfs) is
//! unchanged and unaffected — this is the standard posture for headless
//! Chromium in containers and is not a `NET CAPABILITY EXCEPTION`-class
//! change. Any Tetragon (or equivalent eBPF) process-execution allowlist
//! gating this pod must additionally admit `chromium` spawning its own
//! child renderer/GPU/zygote processes (`chromium --type=renderer/zygote/
//! gpu-process ...`) or every screenshot will be silently killed at the
//! LSM/eBPF layer instead of failing through this module's own error
//! handling — flagging both the Dockerfile binary install and the
//! Tetragon allowlist update for the chart/Dockerfile owner; neither is
//! done in this change (out of this task's `services/scanner` +
//! `services/manager` scope).
//!
//! **`masscan` requires `CAP_NET_RAW` (or root)** to send raw SYN packets.
//! This module never escalates privileges to compensate for a missing
//! capability: a failed `masscan` spawn surfaces
//! [`AsmError::Spawn`], whose message names the requirement, and the
//! scan is marked `failed` with that message. Cluster operators must grant
//! `NET_RAW` via an explicit, approved `NET CAPABILITY EXCEPTION`
//! `securityContext` (see `devops-containers.md`'s Rootless Containers
//! exception process) for ASM scanning to function — without it, every ASM
//! scan fails closed with this message rather than silently degrading to a
//! different technique or running as root.

use std::collections::HashSet;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use chrono::{NaiveDateTime, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::Digest as _;
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use uuid::Uuid;
use x509_parser::prelude::FromDer as _;

use crate::message::ScannerResult;

/// Well-known ports probed by default when the trigger request supplies no
/// extras — mirrors v1's ASM default surface
/// (`services/worker-scanner/scanners/masscan.py`).
const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433,
    1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 9443, 27017,
];

/// Ports probed for a TLS certificate once masscan reports them open —
/// matches v1 `inspect_cert`'s explicit list.
const TLS_PORTS: &[u16] = &[443, 465, 636, 993, 995, 8443, 9443];

/// Ports treated as HTTP(S) endpoints eligible for the screenshot stage —
/// the web-serving subset of [`DEFAULT_PORTS`], matching the ports
/// [`guess_service_name`] maps to `"http"`/`"https"`/`"http-alt"`/
/// `"https-alt"`. RDP (3389) and VNC (5900) are deliberately excluded — see
/// the module doc's "Screenshot capture" section.
const HTTP_PORTS: &[u16] = &[80, 443, 8080, 8443, 9443];

/// Explicit per-pipeline-stage timeouts and the resolved `masscan` binary
/// path, threaded in from `crate::config::WorkerConfig` by `handler.rs`.
/// Kept as a small owned struct (rather than passing `&WorkerConfig`
/// directly) so this module stays decoupled from the rest of the worker's
/// config surface and is trivially constructible in tests. Not `Debug`
/// (unlike most config structs in this workspace): [`ScreenshotStageConfig`]
/// carries a live `aws_sdk_s3::Client` handle and this struct deliberately
/// doesn't depend on that type's `Debug` impl staying stable across SDK
/// versions; nothing in this codebase formats an `AsmPipelineConfig` with
/// `{:?}`.
#[derive(Clone)]
pub struct AsmPipelineConfig {
    pub masscan_bin: String,
    pub masscan_timeout: Duration,
    pub banner_timeout: Duration,
    pub cert_timeout: Duration,
    /// Screenshot capture stage config, or `None` to skip it entirely
    /// (`ASM_SCREENSHOT_ENABLED=false` or no bucket configured — see
    /// `crate::config::WorkerConfig`).
    pub screenshot: Option<ScreenshotStageConfig>,
}

/// Screenshot-stage settings: the `chromium` binary/timeout/viewport plus
/// the [`ScreenshotUploader`] that puts captured bytes in S3.
#[derive(Clone)]
pub struct ScreenshotStageConfig {
    pub chromium_bin: String,
    pub timeout: Duration,
    pub window_width: u32,
    pub window_height: u32,
    pub uploader: ScreenshotUploader,
}

/// Wraps an `aws_sdk_s3::Client` + target bucket for screenshot uploads.
/// The client is built once at worker startup (`main.rs::serve`, via
/// `skauswatch_s3::client`) and cloned per-task — `aws_sdk_s3::Client` is a
/// cheap `Arc`-backed handle, matching how `s3ops`/`s3scan` already reuse
/// clients across calls.
#[derive(Clone)]
pub struct ScreenshotUploader {
    client: S3Client,
    bucket: String,
}

impl ScreenshotUploader {
    /// Builds an uploader targeting `bucket` via `client`.
    #[must_use]
    pub fn new(client: S3Client, bucket: String) -> Self {
        Self { client, bucket }
    }

    /// Uploads `bytes` as `image/png` at `key`. Best-effort — the caller
    /// (`persist_findings`) logs and continues on error rather than failing
    /// the scan; see the module doc's fail-safe note.
    async fn upload(&self, key: &str, bytes: Vec<u8>) -> Result<(), ScreenshotUploadError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type("image/png")
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map(|_| ())
            .map_err(|e| ScreenshotUploadError::Put(e.to_string()))
    }
}

/// Error uploading a captured screenshot to S3 — always non-fatal to the
/// enclosing scan (see module doc).
#[derive(Debug, thiserror::Error)]
pub enum ScreenshotUploadError {
    #[error("s3 put_object failed: {0}")]
    Put(String),
}

// ============================================
// masscan
// ============================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenPort {
    ip: String,
    port: u16,
    protocol: String,
}

/// Errors from the masscan stage. Each variant renders a message safe to
/// store verbatim in `asm_scans.error_message` and surface to an operator.
#[derive(Debug, thiserror::Error)]
pub enum AsmError {
    #[error(
        "masscan binary '{bin}' unavailable: {source} — port scanning requires CAP_NET_RAW \
         (or root) to send raw SYN packets; this worker does not escalate privileges to \
         compensate. Grant NET_RAW via an explicit, approved 'NET CAPABILITY EXCEPTION' \
         securityContext (see devops-containers.md) if ASM scanning is required."
    )]
    Spawn {
        bin: String,
        #[source]
        source: std::io::Error,
    },
    #[error("masscan exited with status {status}: {stderr}")]
    Exit { status: i32, stderr: String },
    #[error("masscan invocation timed out after {0:?}")]
    Timeout(Duration),
}

/// Builds masscan's argument list: `-p <ports> --rate <rate> -oJ - <target>`.
fn build_masscan_args(target: &str, ports: &[u16], rate: i64) -> Vec<String> {
    let port_list = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    vec![
        "-p".to_owned(),
        port_list,
        "--rate".to_owned(),
        rate.to_string(),
        "-oJ".to_owned(),
        "-".to_owned(),
        target.to_owned(),
    ]
}

/// Parses masscan's `-oJ -` output: one JSON object per discovered host per
/// line (masscan wraps the whole stream in `[ ... ]` with a trailing comma
/// after all but the last record), so this parses line-by-line rather than
/// as one JSON document — tolerant of the leading `[`/trailing `]` framing
/// lines and any trailing comma.
fn parse_masscan_output(raw: &str) -> Vec<OpenPort> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim().trim_end_matches(',');
        if !line.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(ip) = v.get("ip").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(ports) = v.get("ports").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for p in ports {
            let port = p.get("port").and_then(serde_json::Value::as_u64);
            let proto = p.get("proto").and_then(serde_json::Value::as_str);
            let status = p.get("status").and_then(serde_json::Value::as_str);
            let (Some(port), Some(proto), Some("open")) = (port, proto, status) else {
                continue;
            };
            let Ok(port) = u16::try_from(port) else {
                continue;
            };
            out.push(OpenPort {
                ip: ip.to_owned(),
                port,
                protocol: proto.to_owned(),
            });
        }
    }
    out
}

/// Runs `masscan` and parses its output. `bin` is caller-resolved (never
/// read from the environment here) so tests can point it at a fake
/// executable — see the `tests` module.
async fn run_masscan(
    bin: &str,
    target: &str,
    ports: &[u16],
    rate: i64,
    timeout: Duration,
) -> Result<Vec<OpenPort>, AsmError> {
    let args = build_masscan_args(target, ports, rate);
    let run = async {
        // A handful of retries on `ETXTBSY` ("Text file busy"): transient
        // in production (e.g. mid package-manager upgrade of the masscan
        // binary), and observed as a genuine race under this environment's
        // container/overlay filesystem in tests that write-then-immediately
        // -exec a fake binary — closing a write handle and exec-ing the
        // same path back-to-back occasionally races the kernel's busy-text
        // bookkeeping. A real, stable `masscan` install never exhibits this.
        let mut attempts_left = 3u8;
        let output = loop {
            let spawn = Command::new(bin)
                .args(&args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .output()
                .await;
            match spawn {
                Ok(output) => break output,
                Err(source)
                    if attempts_left > 1
                        && source.raw_os_error() == Some(26 /* ETXTBSY */) =>
                {
                    attempts_left -= 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(source) => {
                    return Err(AsmError::Spawn {
                        bin: bin.to_owned(),
                        source,
                    });
                }
            }
        };
        if !output.status.success() {
            return Err(AsmError::Exit {
                status: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(parse_masscan_output(&String::from_utf8_lossy(
            &output.stdout,
        )))
    };
    match tokio::time::timeout(timeout, run).await {
        Ok(res) => res,
        Err(_) => Err(AsmError::Timeout(timeout)),
    }
}

// ============================================
// Banner grab
// ============================================

/// Best-effort TCP banner grab: connects, sends a harmless CRLF nudge (some
/// protocols like HTTP wait for input before responding), then reads
/// whatever arrives within `timeout`. Returns `None` on any connect/read
/// failure or timeout — banner absence is not a pipeline error, it just
/// means `asm_services.banner` stays null for that port.
async fn grab_banner(ip: &str, port: u16, timeout: Duration) -> Option<String> {
    let addr = format!("{ip}:{port}");
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;
    let _ = stream.write_all(b"\r\n").await;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let text = String::from_utf8_lossy(&buf[..n]).trim().to_owned();
    if text.is_empty() { None } else { Some(text) }
}

/// Static service-name guess for a subset of [`DEFAULT_PORTS`] — cosmetic
/// only (`asm_services.service_name`); never used for scan logic.
fn guess_service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        587 => "submission",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        9200 => "elasticsearch",
        9443 => "https-alt",
        27017 => "mongodb",
        _ => return None,
    })
}

// ============================================
// TLS certificate inspection
// ============================================

/// Accepts any certificate chain without validating trust — this client
/// exists to passively *inspect* whatever certificate a service presents
/// (subject, issuer, expiry, SANs), the same posture as
/// `openssl s_client -connect` or v1's `cert_inspector.py`. Chain/trust
/// validation is out of scope for a port scanner; it is not the security
/// boundary here.
#[derive(Debug)]
struct AcceptAllVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
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

fn insecure_tls_config() -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(AcceptAllVerifier {
        provider: Arc::clone(&provider),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Parsed TLS certificate fields — mirrors `asm_certs`' columns.
#[derive(Debug, Clone, PartialEq)]
struct CertInfo {
    subject: String,
    issuer: String,
    not_before: Option<NaiveDateTime>,
    not_after: Option<NaiveDateTime>,
    is_expired: bool,
    days_until_expiry: Option<i32>,
    sans: Vec<String>,
    fingerprint_sha256: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses one leaf certificate's DER bytes into [`CertInfo`]. Subject/issuer
/// use x509-parser's `Display` (a readable, not byte-exact-RFC4514, DN
/// rendering) — sufficient for the inspection/display use this feature has;
/// unlike CA issuance (`services/pki`), nothing downstream string-matches
/// against it.
fn parse_cert_der(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let validity = cert.validity();
    let not_before = chrono::DateTime::from_timestamp(validity.not_before.timestamp(), 0)
        .map(|dt| dt.naive_utc());
    let not_after = chrono::DateTime::from_timestamp(validity.not_after.timestamp(), 0)
        .map(|dt| dt.naive_utc());
    let now = Utc::now().naive_utc();
    let is_expired = not_after.is_some_and(|na| now > na);
    let days_until_expiry = not_after.map(|na| ((na - now).num_seconds() / 86_400) as i32);
    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    x509_parser::extensions::GeneralName::DNSName(d) => Some((*d).to_owned()),
                    x509_parser::extensions::GeneralName::IPAddress(ip) => {
                        Some(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let fingerprint_sha256 = hex_encode(&sha2::Sha256::digest(der));
    Some(CertInfo {
        subject,
        issuer,
        not_before,
        not_after,
        is_expired,
        days_until_expiry,
        sans,
        fingerprint_sha256,
    })
}

/// Connects to `ip:port`, performs a TLS handshake (SNI = `ip` — this
/// worker has no hostname for a masscan-discovered IP), and inspects the
/// peer's leaf certificate. Returns `None` on any failure (not a TLS
/// service, connect/handshake timeout, ...) — a missing cert is not a
/// pipeline error.
async fn fetch_cert_info(ip: &str, port: u16, timeout: Duration) -> Option<CertInfo> {
    let config = insecure_tls_config().ok()?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let addr = format!("{ip}:{port}");
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;
    let server_name = ServerName::try_from(ip.to_owned()).ok()?;
    let tls = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .ok()?
        .ok()?;
    let (_, session) = tls.get_ref();
    let certs = session.peer_certificates()?;
    let leaf = certs.first()?;
    parse_cert_der(leaf.as_ref())
}

// ============================================
// Screenshot capture (headless chromium)
// ============================================

/// Errors from the screenshot-capture stage. Every variant is fail-safe at
/// the call site — never propagated as a scan-level error, only logged.
#[derive(Debug, thiserror::Error)]
pub enum ScreenshotError {
    #[error("chromium binary '{bin}' unavailable: {source}")]
    Spawn {
        bin: String,
        #[source]
        source: std::io::Error,
    },
    #[error("chromium exited with status {status}: {stderr}")]
    Exit { status: i32, stderr: String },
    #[error("chromium screenshot capture timed out after {0:?}")]
    Timeout(Duration),
    #[error("failed to read captured screenshot file: {0}")]
    Read(#[source] std::io::Error),
    #[error("chromium produced an empty screenshot file")]
    Empty,
}

/// Maps an HTTP(S) [`HTTP_PORTS`] port to the URL chromium should load.
/// Uses the bare IP as host (masscan discovers IPs, not hostnames) with
/// `https://` for the TLS-coded ports and `http://` otherwise. Returns
/// `None` for any port outside [`HTTP_PORTS`].
fn http_url_for_port(ip: &str, port: u16) -> Option<String> {
    if !HTTP_PORTS.contains(&port) {
        return None;
    }
    // Reuses [`TLS_PORTS`] (already the source of truth for "does this port
    // speak TLS" via the cert-inspection stage above) rather than defining a
    // third ports list for the same 443/8443/9443 subset.
    let scheme = if TLS_PORTS.contains(&port) {
        "https"
    } else {
        "http"
    };
    Some(format!("{scheme}://{ip}:{port}"))
}

/// Runs headless `chromium` against `url` and returns the captured PNG
/// bytes. `bin` is caller-resolved (never read from the environment here)
/// so tests can point it at a fake executable — see the `tests` module.
///
/// `--no-sandbox` is required under this workspace's rootless container
/// posture (see module doc); `--ignore-certificate-errors` because ASM
/// targets are arbitrary discovered hosts, frequently self-signed or
/// expired (same posture as [`AcceptAllVerifier`] above — capture is
/// inspection, not a trust decision); `--virtual-time-budget` bounds how
/// long chromium waits for the page to settle before capturing, deriving
/// from `timeout` so the two never disagree.
async fn capture_screenshot(
    bin: &str,
    url: &str,
    width: u32,
    height: u32,
    timeout: Duration,
) -> Result<Vec<u8>, ScreenshotError> {
    let out_file = tempfile::Builder::new()
        .suffix(".png")
        .tempfile()
        .map_err(ScreenshotError::Read)?;
    let out_path = out_file.path().to_path_buf();

    let budget_ms = timeout.as_millis().min(u128::from(u32::MAX)) as u64;
    let args = vec![
        "--headless".to_owned(),
        "--disable-gpu".to_owned(),
        "--no-sandbox".to_owned(),
        "--disable-dev-shm-usage".to_owned(),
        "--hide-scrollbars".to_owned(),
        "--disable-extensions".to_owned(),
        "--ignore-certificate-errors".to_owned(),
        format!("--window-size={width},{height}"),
        format!("--virtual-time-budget={budget_ms}"),
        format!("--screenshot={}", out_path.display()),
        url.to_owned(),
    ];

    let run = async {
        // Same ETXTBSY retry as `run_masscan` above: tests exec a freshly
        // written-and-chmod'd fake `chromium` binary immediately after
        // creating it, which races the kernel's busy-text bookkeeping on
        // this environment's container/overlay filesystem — worse under
        // `cargo llvm-cov`'s instrumented, slower binaries where more tests
        // run concurrently and widen the window. A real, stable `chromium`
        // install never exhibits this. Without the retry, a transient
        // ETXTBSY surfaces as `ScreenshotError::Spawn` instead of the
        // `Exit`/`Timeout`/success outcome the caller (and its tests)
        // actually expect.
        let mut attempts_left = 3u8;
        let output = loop {
            let spawn = Command::new(bin)
                .args(&args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .output()
                .await;
            match spawn {
                Ok(output) => break output,
                Err(source)
                    if attempts_left > 1
                        && source.raw_os_error() == Some(26 /* ETXTBSY */) =>
                {
                    attempts_left -= 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(source) => {
                    return Err(ScreenshotError::Spawn {
                        bin: bin.to_owned(),
                        source,
                    });
                }
            }
        };
        if !output.status.success() {
            return Err(ScreenshotError::Exit {
                status: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        let bytes = tokio::fs::read(&out_path)
            .await
            .map_err(ScreenshotError::Read)?;
        if bytes.is_empty() {
            return Err(ScreenshotError::Empty);
        }
        Ok(bytes)
    };
    match tokio::time::timeout(timeout, run).await {
        Ok(res) => res,
        Err(_) => Err(ScreenshotError::Timeout(timeout)),
    }
}

// ============================================
// Pipeline orchestration
// ============================================

/// One target-port's full findings — a service row plus its cert and
/// screenshot, if any.
struct ServiceFinding {
    ip: String,
    port: u16,
    protocol: String,
    banner: Option<String>,
    cert: Option<CertInfo>,
    screenshot: Option<ScreenshotCapture>,
}

/// A successfully captured screenshot, pending upload — mirrors
/// `asm_screenshots`' columns not already implied by the owning service row.
struct ScreenshotCapture {
    bytes: Vec<u8>,
    tool: String,
    width: u32,
    height: u32,
}

/// Resolves the effective port list: [`DEFAULT_PORTS`] plus any
/// caller-supplied `extra_ports` (out-of-range/invalid values silently
/// dropped — `routes/asm.rs` already validates them before publishing, this
/// is defense in depth), deduplicated.
fn effective_ports(extra_ports: &[i64]) -> Vec<u16> {
    let mut set: HashSet<u16> = DEFAULT_PORTS.iter().copied().collect();
    for p in extra_ports {
        if let Ok(p) = u16::try_from(*p)
            && p >= 1
        {
            set.insert(p);
        }
    }
    let mut ports: Vec<u16> = set.into_iter().collect();
    ports.sort_unstable();
    ports
}

/// Runs the full pipeline for one `asm_scans` row: masscan → per-open-port
/// banner grab (+ TLS cert fetch on [`TLS_PORTS`]) → writes hosts/services/
/// certs → computes and writes a diff against the previous completed scan
/// for the same `(tenant_id, target)` → marks the scan `completed`/`failed`.
/// Returns a [`ScannerResult`] summarizing the run for the generic
/// `scanner_scan_results` log (`job_id` is a placeholder — the caller
/// overwrites it, matching `crate::scan::execute_scan`'s convention).
pub async fn run_asm_scan(
    pool: &PgPool,
    tenant_id: Uuid,
    target: &str,
    params: &serde_json::Value,
    cfg: &AsmPipelineConfig,
) -> ScannerResult {
    let start = std::time::Instant::now();
    let Some(scan_id) = params.get("scan_id").and_then(serde_json::Value::as_i64) else {
        return error_result(target, "missing scan_id in asm task params", start);
    };
    let extra_ports: Vec<i64> = params
        .get("ports_config")
        .and_then(|pc| pc.get("extra_ports"))
        .and_then(serde_json::Value::as_array)
        .map(|a| a.iter().filter_map(serde_json::Value::as_i64).collect())
        .unwrap_or_default();
    let rate = params
        .get("ports_config")
        .and_then(|pc| pc.get("rate"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(1000);
    let ports = effective_ports(&extra_ports);

    let marked_running = sqlx::query(
        "UPDATE asm_scans SET status = 'running', started_at = now() \
         WHERE id = $1 AND tenant_id = $2 AND status = 'pending'",
    )
    .bind(scan_id)
    .bind(tenant_id)
    .execute(pool)
    .await;
    match marked_running {
        Ok(r) if r.rows_affected() == 0 => {
            return error_result(
                target,
                &format!("asm scan {scan_id} not found for tenant, or not pending"),
                start,
            );
        }
        Err(e) => {
            tracing::error!(scan_id, error = %e, "failed to mark asm scan running");
            return error_result(target, &format!("database error: {e}"), start);
        }
        Ok(_) => {}
    }

    let open_ports =
        match run_masscan(&cfg.masscan_bin, target, &ports, rate, cfg.masscan_timeout).await {
            Ok(ports) => ports,
            Err(e) => {
                let msg = e.to_string();
                let _ = sqlx::query(
                "UPDATE asm_scans SET status = 'failed', completed_at = now(), error_message = $3 \
                 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(scan_id)
            .bind(tenant_id)
            .bind(&msg)
            .execute(pool)
            .await;
                return error_result(target, &msg, start);
            }
        };

    // Group by IP, preserving masscan's discovery order for determinism.
    let mut ips: Vec<String> = Vec::new();
    for op in &open_ports {
        if !ips.contains(&op.ip) {
            ips.push(op.ip.clone());
        }
    }

    let mut findings: Vec<ServiceFinding> = Vec::new();
    for ip in &ips {
        for op in open_ports.iter().filter(|o| &o.ip == ip) {
            let banner = grab_banner(&op.ip, op.port, cfg.banner_timeout).await;
            let cert = if TLS_PORTS.contains(&op.port) {
                fetch_cert_info(&op.ip, op.port, cfg.cert_timeout).await
            } else {
                None
            };
            let screenshot = match (&cfg.screenshot, http_url_for_port(&op.ip, op.port)) {
                (Some(sc), Some(url)) => {
                    match capture_screenshot(
                        &sc.chromium_bin,
                        &url,
                        sc.window_width,
                        sc.window_height,
                        sc.timeout,
                    )
                    .await
                    {
                        Ok(bytes) => Some(ScreenshotCapture {
                            bytes,
                            tool: "chromium-headless".to_owned(),
                            width: sc.window_width,
                            height: sc.window_height,
                        }),
                        Err(e) => {
                            // Fail-safe: one host's screenshot failure never
                            // aborts the scan — log and keep going with no
                            // screenshot for this service.
                            tracing::warn!(
                                ip = %op.ip, port = op.port, error = %e,
                                "asm screenshot capture failed, continuing scan"
                            );
                            None
                        }
                    }
                }
                _ => None,
            };
            findings.push(ServiceFinding {
                ip: op.ip.clone(),
                port: op.port,
                protocol: op.protocol.clone(),
                banner,
                cert,
                screenshot,
            });
        }
    }

    if let Err(e) = persist_findings(pool, tenant_id, scan_id, &ips, &findings, cfg).await {
        let msg = format!("failed to persist asm findings: {e}");
        let _ = sqlx::query(
            "UPDATE asm_scans SET status = 'failed', completed_at = now(), error_message = $3 \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(scan_id)
        .bind(tenant_id)
        .bind(&msg)
        .execute(pool)
        .await;
        return error_result(target, &msg, start);
    }

    if let Err(e) = compute_and_store_diff(pool, tenant_id, scan_id, target, &findings).await {
        // Diff failure is not scan failure — the primary findings are
        // already persisted and useful on their own.
        tracing::warn!(scan_id, error = %e, "asm diff computation failed");
    }

    let _ = sqlx::query(
        "UPDATE asm_scans SET status = 'completed', completed_at = now() \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(scan_id)
    .bind(tenant_id)
    .execute(pool)
    .await;

    ScannerResult {
        job_id: target.to_owned(),
        scan_type: "asm".to_owned(),
        findings_count: findings.len(),
        findings: serde_json::json!({
            "scan_id": scan_id,
            "hosts": ips.len(),
            "services": findings.len(),
            "certs": findings.iter().filter(|f| f.cert.is_some()).count(),
        }),
        duration_sec: start.elapsed().as_secs_f64(),
        status: "success".to_owned(),
        error_message: None,
        timestamp: Utc::now().to_rfc3339(),
    }
}

fn error_result(target: &str, message: &str, start: std::time::Instant) -> ScannerResult {
    ScannerResult {
        job_id: target.to_owned(),
        scan_type: "asm".to_owned(),
        findings_count: 0,
        findings: serde_json::json!({}),
        duration_sec: start.elapsed().as_secs_f64(),
        status: "error".to_owned(),
        error_message: Some(message.to_owned()),
        timestamp: Utc::now().to_rfc3339(),
    }
}

/// Writes one `asm_hosts` row per unique IP and one `asm_services`/
/// `asm_certs`/`asm_screenshots` row per discovered open port.
async fn persist_findings(
    pool: &PgPool,
    tenant_id: Uuid,
    scan_id: i64,
    ips: &[String],
    findings: &[ServiceFinding],
    cfg: &AsmPipelineConfig,
) -> Result<(), sqlx::Error> {
    for ip in ips {
        let host_id: i64 = sqlx::query_scalar(
            "INSERT INTO asm_hosts (scan_id, tenant_id, ip_address, is_alive, created_at) \
             VALUES ($1, $2, $3, TRUE, now()) RETURNING id",
        )
        .bind(scan_id)
        .bind(tenant_id)
        .bind(ip)
        .fetch_one(pool)
        .await?;

        for f in findings.iter().filter(|f| &f.ip == ip) {
            let service_id: i64 = sqlx::query_scalar(
                "INSERT INTO asm_services \
                 (host_id, tenant_id, port, protocol, state, service_name, banner, created_at) \
                 VALUES ($1, $2, $3, $4, 'open', $5, $6, now()) RETURNING id",
            )
            .bind(host_id)
            .bind(tenant_id)
            .bind(i32::from(f.port))
            .bind(&f.protocol)
            .bind(guess_service_name(f.port))
            .bind(&f.banner)
            .fetch_one(pool)
            .await?;

            if let Some(cert) = &f.cert {
                sqlx::query(
                    "INSERT INTO asm_certs \
                     (service_id, tenant_id, subject, issuer, not_before, not_after, \
                      is_expired, days_until_expiry, sans, fingerprint_sha256, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())",
                )
                .bind(service_id)
                .bind(tenant_id)
                .bind(&cert.subject)
                .bind(&cert.issuer)
                .bind(cert.not_before)
                .bind(cert.not_after)
                .bind(cert.is_expired)
                .bind(cert.days_until_expiry)
                .bind(serde_json::Value::from(cert.sans.clone()))
                .bind(&cert.fingerprint_sha256)
                .execute(pool)
                .await?;
            }

            // Screenshot upload is best-effort: an S3 failure here logs and
            // moves on (no `asm_screenshots` row for this service) rather
            // than failing the whole scan — the primary findings above are
            // already persisted. Only reachable when both a screenshot was
            // actually captured (`f.screenshot`) and the stage is
            // configured (`cfg.screenshot`) — the latter is always `Some`
            // whenever the former is, since capture only runs under
            // `cfg.screenshot.is_some()`, but checked again here defensively
            // rather than assumed.
            if let (Some(shot), Some(stage)) = (&f.screenshot, &cfg.screenshot) {
                let key = format!("asm/{tenant_id}/{scan_id}/{service_id}.png");
                match stage.uploader.upload(&key, shot.bytes.clone()).await {
                    Ok(()) => {
                        sqlx::query(
                            "INSERT INTO asm_screenshots \
                             (service_id, tenant_id, s3_key, tool, width, height, \
                              file_size_bytes, captured_at, created_at) \
                             VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())",
                        )
                        .bind(service_id)
                        .bind(tenant_id)
                        .bind(&key)
                        .bind(&shot.tool)
                        .bind(shot.width as i32)
                        .bind(shot.height as i32)
                        .bind(shot.bytes.len() as i32)
                        .execute(pool)
                        .await?;
                    }
                    Err(e) => {
                        tracing::warn!(
                            service_id, error = %e,
                            "asm screenshot upload failed, continuing scan"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Finds the previous *completed* scan for the same `(tenant_id, target)`
/// (excluding this scan), diffs services (`ip:port:protocol` set) and
/// certs (by SHA-256 fingerprint), and writes one `asm_diffs` row.
/// `expired_certs` reports every currently-expired cert in *this* scan
/// (not just newly-expired since the prior one) — the operationally useful
/// question ("what's expired right now") rather than a stricter
/// newly-expired-only reading; documented here since v1's dead code never
/// actually exercised this semantic. No-ops (no row written) when there is
/// no prior completed scan — a diff needs a baseline.
async fn compute_and_store_diff(
    pool: &PgPool,
    tenant_id: Uuid,
    scan_id: i64,
    target: &str,
    findings: &[ServiceFinding],
) -> Result<(), sqlx::Error> {
    let prev_scan_id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM asm_scans WHERE tenant_id = $1 AND target = $2 AND status = 'completed' \
         AND id != $3 ORDER BY completed_at DESC NULLS LAST, id DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(target)
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    let Some(prev_scan_id) = prev_scan_id else {
        return Ok(());
    };

    let prev_services: Vec<(String, i32, String)> = sqlx::query_as(
        "SELECT h.ip_address, s.port, s.protocol FROM asm_hosts h \
         JOIN asm_services s ON s.host_id = h.id \
         WHERE h.scan_id = $1 AND h.tenant_id = $2",
    )
    .bind(prev_scan_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    let prev_set: HashSet<(String, i32, String)> = prev_services.into_iter().collect();

    let curr_set: HashSet<(String, i32, String)> = findings
        .iter()
        .map(|f| (f.ip.clone(), i32::from(f.port), f.protocol.clone()))
        .collect();

    let new_services: Vec<serde_json::Value> = curr_set
        .difference(&prev_set)
        .map(|(ip, port, proto)| serde_json::json!({"ip": ip, "port": port, "protocol": proto}))
        .collect();
    let removed_services: Vec<serde_json::Value> = prev_set
        .difference(&curr_set)
        .map(|(ip, port, proto)| serde_json::json!({"ip": ip, "port": port, "protocol": proto}))
        .collect();

    let prev_fingerprints: HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT c.fingerprint_sha256 FROM asm_certs c \
         JOIN asm_services s ON s.id = c.service_id \
         JOIN asm_hosts h ON h.id = s.host_id \
         WHERE h.scan_id = $1 AND h.tenant_id = $2 AND c.fingerprint_sha256 IS NOT NULL",
    )
    .bind(prev_scan_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    let mut new_certs = Vec::new();
    let mut expired_certs = Vec::new();
    for f in findings {
        let Some(cert) = &f.cert else { continue };
        let entry = serde_json::json!({
            "ip": f.ip, "port": f.port, "fingerprint_sha256": cert.fingerprint_sha256,
        });
        if !prev_fingerprints.contains(&cert.fingerprint_sha256) {
            new_certs.push(entry.clone());
        }
        if cert.is_expired {
            expired_certs.push(entry);
        }
    }

    sqlx::query(
        "INSERT INTO asm_diffs \
         (scan_id, tenant_id, prev_scan_id, new_services, removed_services, new_certs, \
          expired_certs, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now())",
    )
    .bind(scan_id)
    .bind(tenant_id)
    .bind(prev_scan_id)
    .bind(serde_json::Value::from(new_services))
    .bind(serde_json::Value::from(removed_services))
    .bind(serde_json::Value::from(new_certs))
    .bind(serde_json::Value::from(expired_certs))
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use wiremock::matchers::{method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ---------- pure parsing/arg-building ----------

    #[test]
    fn build_masscan_args_shape() {
        let args = build_masscan_args("10.0.0.0/24", &[22, 80, 443], 500);
        assert_eq!(
            args,
            vec![
                "-p",
                "22,80,443",
                "--rate",
                "500",
                "-oJ",
                "-",
                "10.0.0.0/24"
            ]
        );
    }

    #[test]
    fn parse_masscan_output_extracts_open_ports_and_skips_closed() {
        let raw = r#"[
{ "ip": "203.0.113.5", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] },
{ "ip": "203.0.113.6", "ports": [ {"port": 22, "proto": "tcp", "status": "closed"} ] },
{ "ip": "203.0.113.5", "ports": [ {"port": 443, "proto": "tcp", "status": "open"} ] }
]"#;
        let ports = parse_masscan_output(raw);
        assert_eq!(
            ports,
            vec![
                OpenPort {
                    ip: "203.0.113.5".into(),
                    port: 80,
                    protocol: "tcp".into()
                },
                OpenPort {
                    ip: "203.0.113.5".into(),
                    port: 443,
                    protocol: "tcp".into()
                },
            ]
        );
    }

    #[test]
    fn parse_masscan_output_ignores_malformed_lines() {
        let raw = "not json\n{\"ip\": \"1.2.3.4\"}\n{}\n";
        assert!(parse_masscan_output(raw).is_empty());
    }

    #[test]
    fn effective_ports_merges_defaults_and_extras_deduplicated() {
        let ports = effective_ports(&[80, 99999, 0, 8080]);
        assert!(ports.contains(&80));
        assert!(ports.contains(&8080));
        assert!(!ports.contains(&0));
        assert!(ports.iter().filter(|p| **p == 80).count() == 1);
    }

    #[test]
    fn guess_service_name_known_and_unknown() {
        assert_eq!(guess_service_name(443), Some("https"));
        assert_eq!(guess_service_name(65000), None);
    }

    #[test]
    fn hex_encode_matches_known_vector() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // ---------- masscan subprocess (fake binary — real masscan needs NET_RAW) ----------

    /// Writes an executable shell script at a temp path that, regardless of
    /// its arguments, prints `stdout` to stdout and exits with `code`.
    /// Reserves a unique temp path, writes the script content through a
    /// separate, explicitly-scoped (and `sync_all`ed) file handle, then
    /// chmods and returns the bare `TempPath` with no open handle at all.
    /// Exec-ing a path that still has *any* open write handle — even one
    /// nominally "closed" via `NamedTempFile::into_temp_path` — proved
    /// flaky under this container's overlay filesystem (intermittent
    /// `ETXTBSY`/"Text file busy"); this fully separates write-and-close
    /// from path reservation, which does not.
    fn fake_binary(stdout: &str, code: i32) -> tempfile::TempPath {
        let path = tempfile::NamedTempFile::new()
            .expect("tempfile")
            .into_temp_path();
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open for write");
            writeln!(file, "#!/bin/sh").expect("write");
            writeln!(file, "cat <<'EOF'\n{stdout}\nEOF").expect("write");
            writeln!(file, "exit {code}").expect("write");
            file.sync_all().expect("sync");
        }
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");
        path
    }

    #[tokio::test]
    async fn run_masscan_parses_fake_binary_output() {
        let script = fake_binary(
            r#"[
{ "ip": "198.51.100.9", "ports": [ {"port": 22, "proto": "tcp", "status": "open"} ] }
]"#,
            0,
        );
        let bin = script.to_str().expect("utf8 path").to_owned();
        let ports = run_masscan(&bin, "198.51.100.9", &[22], 1000, Duration::from_secs(5))
            .await
            .expect("masscan succeeds");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].ip, "198.51.100.9");
        assert_eq!(ports[0].port, 22);
    }

    #[tokio::test]
    async fn run_masscan_missing_binary_names_net_raw_requirement() {
        let err = run_masscan(
            "/nonexistent/definitely-not-masscan",
            "target",
            &[22],
            1000,
            Duration::from_secs(5),
        )
        .await
        .expect_err("spawn must fail");
        assert!(matches!(err, AsmError::Spawn { .. }));
        assert!(err.to_string().contains("NET_RAW"));
    }

    #[tokio::test]
    async fn run_masscan_nonzero_exit_is_reported() {
        let script = fake_binary("irrelevant", 1);
        let bin = script.to_str().expect("utf8 path").to_owned();
        let err = run_masscan(&bin, "target", &[22], 1000, Duration::from_secs(5))
            .await
            .expect_err("nonzero exit must fail");
        assert!(matches!(err, AsmError::Exit { status: 1, .. }));
    }

    #[tokio::test]
    async fn run_masscan_times_out() {
        let path = fake_binary("irrelevant", 0);
        // Overwrite with a sleeping script (fake_binary's own content would
        // exit immediately) via the same write-then-close-then-chmod
        // sequence as fake_binary itself.
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .expect("open for write");
            writeln!(file, "#!/bin/sh\nsleep 5\n").expect("write");
            file.sync_all().expect("sync");
        }
        let bin = path.to_str().expect("utf8 path").to_owned();
        let err = run_masscan(&bin, "target", &[22], 1000, Duration::from_millis(100))
            .await
            .expect_err("must time out");
        assert!(matches!(err, AsmError::Timeout(_)));
    }

    // ---------- banner grab ----------

    #[tokio::test]
    async fn grab_banner_reads_immediate_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            sock.write_all(b"SSH-2.0-OpenSSH_9.0\r\n")
                .await
                .expect("write");
        });
        let banner = grab_banner(&addr.ip().to_string(), addr.port(), Duration::from_secs(2)).await;
        assert_eq!(banner.as_deref(), Some("SSH-2.0-OpenSSH_9.0"));
    }

    #[tokio::test]
    async fn grab_banner_none_on_connect_failure() {
        // Nothing listens on this port — connection refused immediately.
        let banner = grab_banner("127.0.0.1", 1, Duration::from_millis(500)).await;
        assert!(banner.is_none());
    }

    #[tokio::test]
    async fn grab_banner_none_on_read_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            // Accept but never write or close — client must time out reading.
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(sock);
        });
        let banner = grab_banner(
            &addr.ip().to_string(),
            addr.port(),
            Duration::from_millis(200),
        )
        .await;
        assert!(banner.is_none());
    }

    // ---------- TLS cert inspection ----------

    /// Builds a self-signed leaf cert (via `rcgen`) and its DER key, plus a
    /// bare `rustls::ServerConfig` presenting it — enough to run a real TLS
    /// handshake in-process without any external service.
    fn self_signed_server_config(
        dns_name: &str,
        not_before_days_from_now: i64,
        not_after_days_from_now: i64,
    ) -> (rustls::ServerConfig, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let mut params = rcgen::CertificateParams::new(vec![dns_name.to_owned()]).expect("params");
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now + time::Duration::days(not_before_days_from_now);
        params.not_after = now + time::Duration::days(not_after_days_from_now);
        let cert = params.self_signed(&key).expect("self sign");
        let der = cert.der().as_ref().to_vec();
        let chain = vec![CertificateDer::from(der.clone())];
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain, key_der)
            .expect("single cert");
        (cfg, der)
    }

    async fn tls_test_server(server_cfg: rustls::ServerConfig) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(mut tls) = acceptor.accept(stream).await
            {
                let mut buf = [0u8; 16];
                let _ = tls.read(&mut buf).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn fetch_cert_info_extracts_subject_and_valid_cert() {
        let (server_cfg, _der) = self_signed_server_config("scanner-test.invalid", -1, 30);
        let addr = tls_test_server(server_cfg).await;
        let info = fetch_cert_info(&addr.ip().to_string(), addr.port(), Duration::from_secs(3))
            .await
            .expect("cert fetched");
        // rcgen's `CertificateParams::new(sans)` populates the DNS SAN list
        // from `sans`, not the Subject DN (which defaults to a generic
        // rcgen placeholder) — assert on the field this actually sets.
        assert!(!info.subject.is_empty());
        assert!(!info.is_expired);
        assert!(info.days_until_expiry.unwrap_or(-1) > 0);
        assert_eq!(info.fingerprint_sha256.len(), 64);
        assert!(info.sans.contains(&"scanner-test.invalid".to_owned()));
    }

    #[tokio::test]
    async fn fetch_cert_info_flags_expired_cert() {
        let (server_cfg, _der) = self_signed_server_config("expired.invalid", -60, -1);
        let addr = tls_test_server(server_cfg).await;
        let info = fetch_cert_info(&addr.ip().to_string(), addr.port(), Duration::from_secs(3))
            .await
            .expect("cert fetched");
        assert!(info.is_expired);
    }

    #[tokio::test]
    async fn fetch_cert_info_none_for_non_tls_service() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            let _ = sock.read(&mut buf).await;
        });
        let info = fetch_cert_info(
            &addr.ip().to_string(),
            addr.port(),
            Duration::from_millis(500),
        )
        .await;
        assert!(info.is_none());
    }

    #[test]
    fn parse_cert_der_rejects_garbage() {
        assert!(parse_cert_der(b"not a certificate").is_none());
    }

    // ---------- screenshot capture (fake chromium — real chromium needs
    // to be installed in the image, unavailable in CI) ----------

    #[test]
    fn http_url_for_port_maps_known_ports_and_rejects_others() {
        assert_eq!(
            http_url_for_port("203.0.113.5", 443),
            Some("https://203.0.113.5:443".to_owned())
        );
        assert_eq!(
            http_url_for_port("203.0.113.5", 8443),
            Some("https://203.0.113.5:8443".to_owned())
        );
        assert_eq!(
            http_url_for_port("203.0.113.5", 80),
            Some("http://203.0.113.5:80".to_owned())
        );
        assert_eq!(http_url_for_port("203.0.113.5", 22), None);
    }

    #[tokio::test]
    async fn capture_screenshot_parses_fake_binary_output() {
        let script = fake_chromium_binary("fake-png-bytes", 0);
        let bin = script.to_str().expect("utf8 path").to_owned();
        let bytes = capture_screenshot(
            &bin,
            "http://example.invalid",
            1280,
            800,
            Duration::from_secs(5),
        )
        .await
        .expect("capture succeeds");
        assert_eq!(bytes, b"fake-png-bytes");
    }

    #[tokio::test]
    async fn capture_screenshot_missing_binary_is_spawn_error() {
        let err = capture_screenshot(
            "/nonexistent/definitely-not-chromium",
            "http://example.invalid",
            1280,
            800,
            Duration::from_secs(5),
        )
        .await
        .expect_err("spawn must fail");
        assert!(matches!(err, ScreenshotError::Spawn { .. }));
    }

    #[tokio::test]
    async fn capture_screenshot_nonzero_exit_is_reported() {
        let script = fake_chromium_binary("irrelevant", 1);
        let bin = script.to_str().expect("utf8 path").to_owned();
        let err = capture_screenshot(
            &bin,
            "http://example.invalid",
            1280,
            800,
            Duration::from_secs(5),
        )
        .await
        .expect_err("nonzero exit must fail");
        assert!(matches!(err, ScreenshotError::Exit { status: 1, .. }));
    }

    #[tokio::test]
    async fn capture_screenshot_empty_output_file_is_error() {
        let script = fake_chromium_binary("", 0);
        let bin = script.to_str().expect("utf8 path").to_owned();
        let err = capture_screenshot(
            &bin,
            "http://example.invalid",
            1280,
            800,
            Duration::from_secs(5),
        )
        .await
        .expect_err("empty file must fail");
        assert!(matches!(err, ScreenshotError::Empty));
    }

    #[tokio::test]
    async fn capture_screenshot_times_out() {
        let path = fake_chromium_binary("irrelevant", 0);
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .expect("open for write");
            writeln!(file, "#!/bin/sh\nsleep 5\n").expect("write");
            file.sync_all().expect("sync");
        }
        let bin = path.to_str().expect("utf8 path").to_owned();
        let err = capture_screenshot(
            &bin,
            "http://example.invalid",
            1280,
            800,
            Duration::from_millis(100),
        )
        .await
        .expect_err("must time out");
        assert!(matches!(err, ScreenshotError::Timeout(_)));
    }

    #[tokio::test]
    async fn screenshot_uploader_upload_succeeds_on_2xx() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(wm_path("/asm-shots/asm/tenant/1/2.png"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let uploader =
            ScreenshotUploader::new(mock_s3_client(&server.uri()), "asm-shots".to_owned());
        uploader
            .upload("asm/tenant/1/2.png", b"fake-png-bytes".to_vec())
            .await
            .expect("upload succeeds");
    }

    #[tokio::test]
    async fn screenshot_uploader_upload_returns_err_on_http_failure() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(wm_path("/asm-shots/asm/tenant/1/2.png"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let uploader =
            ScreenshotUploader::new(mock_s3_client(&server.uri()), "asm-shots".to_owned());
        let err = uploader
            .upload("asm/tenant/1/2.png", b"fake-png-bytes".to_vec())
            .await
            .expect_err("upload must fail on 5xx");
        assert!(matches!(err, ScreenshotUploadError::Put(_)));
    }

    // ---------- full pipeline (real Postgres; manager's asm_* migrations
    // layered in — this crate has no local migration for them) ----------

    async fn db_pool() -> sqlx::PgPool {
        skauswatch_testkit::db::test_pool_multi(&[
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")),
            std::path::Path::new(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../manager/migrations"
            )),
        ])
        .await
    }

    const TENANT_A: &str = "00000000-0000-0000-0000-0000000000aa";
    const TENANT_B: &str = "00000000-0000-0000-0000-0000000000bb";

    fn tenant_uuid(s: &str) -> Uuid {
        s.parse().expect("valid uuid literal")
    }

    /// Seeds the tenant row (`asm_scans.tenant_id` FK-references
    /// `tenants(id)` — a manager-owned table) then a pending `asm_scans`
    /// row for it.
    async fn seed_pending_scan(pool: &sqlx::PgPool, tenant: Uuid, target: &str) -> i64 {
        sqlx::query(
            "INSERT INTO tenants (id, slug, name, status) \
             VALUES ($1, $2, $2, 'active') ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(tenant.to_string())
        .execute(pool)
        .await
        .expect("seed tenant");
        sqlx::query_scalar(
            "INSERT INTO asm_scans (tenant_id, target, mode, status, created_at) \
             VALUES ($1, $2, 'external', 'pending', now()) RETURNING id",
        )
        .bind(tenant)
        .bind(target)
        .fetch_one(pool)
        .await
        .expect("seed scan")
    }

    fn test_cfg(masscan_bin: &str) -> AsmPipelineConfig {
        AsmPipelineConfig {
            masscan_bin: masscan_bin.to_owned(),
            masscan_timeout: Duration::from_secs(10),
            banner_timeout: Duration::from_millis(300),
            cert_timeout: Duration::from_millis(300),
            screenshot: None,
        }
    }

    /// Like [`test_cfg`] but with the screenshot stage enabled, pointed at
    /// `chromium_bin` and uploading through `uploader`.
    fn test_cfg_with_screenshot(
        masscan_bin: &str,
        chromium_bin: &str,
        uploader: ScreenshotUploader,
    ) -> AsmPipelineConfig {
        AsmPipelineConfig {
            screenshot: Some(ScreenshotStageConfig {
                chromium_bin: chromium_bin.to_owned(),
                timeout: Duration::from_secs(5),
                window_width: 1280,
                window_height: 800,
                uploader,
            }),
            ..test_cfg(masscan_bin)
        }
    }

    /// Builds an `aws_sdk_s3::Client` pointed at a mock server — same
    /// construction as `services/s3scan/src/s3ops.rs`'s `mock_client` test
    /// helper (dummy static credentials, path-style addressing, no real
    /// AWS calls).
    fn mock_s3_client(uri: &str) -> S3Client {
        let creds =
            aws_sdk_s3::config::Credentials::new("AKTEST", "SKTEST", None, None, "asm-test");
        let cfg = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .endpoint_url(uri)
            .force_path_style(true)
            .credentials_provider(creds)
            .build();
        S3Client::from_conf(cfg)
    }

    /// Writes an executable shell script that scans its args for
    /// `--screenshot=<path>` and writes `contents` there (a stand-in for
    /// real PNG bytes — this module never decodes the file, only reads its
    /// bytes and records the configured viewport as width/height), then
    /// exits with `code`. Same write-then-close-then-chmod sequence as
    /// [`fake_binary`] (avoids the `ETXTBSY` race documented there).
    fn fake_chromium_binary(contents: &str, code: i32) -> tempfile::TempPath {
        let path = tempfile::NamedTempFile::new()
            .expect("tempfile")
            .into_temp_path();
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open for write");
            writeln!(file, "#!/bin/sh").expect("write");
            writeln!(file, "for arg in \"$@\"; do").expect("write");
            writeln!(file, "  case \"$arg\" in").expect("write");
            writeln!(
                file,
                "    --screenshot=*) path=\"${{arg#--screenshot=}}\" ;;"
            )
            .expect("write");
            writeln!(file, "  esac").expect("write");
            writeln!(file, "done").expect("write");
            writeln!(file, "if [ -n \"$path\" ]; then").expect("write");
            writeln!(file, "  printf '{contents}' > \"$path\"").expect("write");
            writeln!(file, "fi").expect("write");
            writeln!(file, "exit {code}").expect("write");
            file.sync_all().expect("sync");
        }
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");
        path
    }

    #[tokio::test]
    async fn run_asm_scan_persists_hosts_and_services_and_completes() {
        let pool = db_pool().await;
        let tenant = tenant_uuid(TENANT_A);
        let scan_id = seed_pending_scan(&pool, tenant, "198.51.100.10").await;

        let script = fake_binary(
            r#"[
{ "ip": "198.51.100.10", "ports": [ {"port": 22, "proto": "tcp", "status": "open"} ] }
]"#,
            0,
        );
        let bin = script.to_str().expect("utf8 path").to_owned();
        let cfg = test_cfg(&bin);

        let result = run_asm_scan(
            &pool,
            tenant,
            "198.51.100.10",
            &serde_json::json!({"scan_id": scan_id, "mode": "external", "ports_config": {}}),
            &cfg,
        )
        .await;
        assert_eq!(result.status, "success");
        assert_eq!(result.findings_count, 1);

        let status: String = sqlx::query_scalar("SELECT status FROM asm_scans WHERE id = $1")
            .bind(scan_id)
            .fetch_one(&pool)
            .await
            .expect("scan row");
        assert_eq!(status, "completed");

        let host_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM asm_hosts WHERE scan_id = $1 AND tenant_id = $2",
        )
        .bind(scan_id)
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("count hosts");
        assert_eq!(host_count, 1);
    }

    #[tokio::test]
    async fn run_asm_scan_missing_scan_id_param_is_error() {
        let pool = db_pool().await;
        let result = run_asm_scan(
            &pool,
            tenant_uuid(TENANT_A),
            "target",
            &serde_json::json!({}),
            &test_cfg("masscan"),
        )
        .await;
        assert_eq!(result.status, "error");
        assert!(result.error_message.unwrap().contains("scan_id"));
    }

    #[tokio::test]
    async fn run_asm_scan_wrong_tenant_cannot_claim_another_tenants_scan() {
        let pool = db_pool().await;
        let owner = tenant_uuid(TENANT_A);
        let attacker = tenant_uuid(TENANT_B);
        let scan_id = seed_pending_scan(&pool, owner, "example.com").await;

        let result = run_asm_scan(
            &pool,
            attacker,
            "example.com",
            &serde_json::json!({"scan_id": scan_id}),
            &test_cfg("masscan"),
        )
        .await;
        assert_eq!(result.status, "error");
        assert!(result.error_message.unwrap().contains("not found"));

        // The real owner's row is untouched (still pending).
        let status: String = sqlx::query_scalar("SELECT status FROM asm_scans WHERE id = $1")
            .bind(scan_id)
            .fetch_one(&pool)
            .await
            .expect("scan row");
        assert_eq!(status, "pending");
    }

    #[tokio::test]
    async fn run_asm_scan_masscan_failure_marks_scan_failed_with_net_raw_message() {
        let pool = db_pool().await;
        let tenant = tenant_uuid(TENANT_A);
        let scan_id = seed_pending_scan(&pool, tenant, "target-fail.example").await;

        let result = run_asm_scan(
            &pool,
            tenant,
            "target-fail.example",
            &serde_json::json!({"scan_id": scan_id}),
            &test_cfg("/nonexistent/definitely-not-masscan"),
        )
        .await;
        assert_eq!(result.status, "error");
        assert!(result.error_message.unwrap().contains("NET_RAW"));

        let row: (String, Option<String>) =
            sqlx::query_as("SELECT status, error_message FROM asm_scans WHERE id = $1")
                .bind(scan_id)
                .fetch_one(&pool)
                .await
                .expect("scan row");
        assert_eq!(row.0, "failed");
        assert!(row.1.expect("error message stored").contains("NET_RAW"));
    }

    #[tokio::test]
    async fn run_asm_scan_second_run_computes_diff_of_removed_service() {
        let pool = db_pool().await;
        let tenant = tenant_uuid(TENANT_A);
        let target = "198.51.100.20";

        // First scan: ports 22 and 80 open.
        let scan1 = seed_pending_scan(&pool, tenant, target).await;
        let script1 = fake_binary(
            r#"[
{ "ip": "198.51.100.20", "ports": [ {"port": 22, "proto": "tcp", "status": "open"} ] },
{ "ip": "198.51.100.20", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] }
]"#,
            0,
        );
        let bin1 = script1.to_str().expect("utf8 path").to_owned();
        let r1 = run_asm_scan(
            &pool,
            tenant,
            target,
            &serde_json::json!({"scan_id": scan1}),
            &test_cfg(&bin1),
        )
        .await;
        assert_eq!(r1.status, "success");

        // Second scan: only port 22 open (80 removed), 443 newly opened.
        let scan2 = seed_pending_scan(&pool, tenant, target).await;
        let script2 = fake_binary(
            r#"[
{ "ip": "198.51.100.20", "ports": [ {"port": 22, "proto": "tcp", "status": "open"} ] },
{ "ip": "198.51.100.20", "ports": [ {"port": 443, "proto": "tcp", "status": "open"} ] }
]"#,
            0,
        );
        let bin2 = script2.to_str().expect("utf8 path").to_owned();
        let r2 = run_asm_scan(
            &pool,
            tenant,
            target,
            &serde_json::json!({"scan_id": scan2}),
            &test_cfg(&bin2),
        )
        .await;
        assert_eq!(r2.status, "success");

        let diff: (Option<i64>, serde_json::Value, serde_json::Value) = sqlx::query_as(
            "SELECT prev_scan_id, new_services, removed_services FROM asm_diffs \
             WHERE scan_id = $1 AND tenant_id = $2",
        )
        .bind(scan2)
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("diff row exists");
        assert_eq!(diff.0, Some(scan1));
        assert_eq!(diff.1.as_array().expect("array").len(), 1);
        assert_eq!(diff.1[0]["port"], 443);
        assert_eq!(diff.2.as_array().expect("array").len(), 1);
        assert_eq!(diff.2[0]["port"], 80);
    }

    #[tokio::test]
    async fn run_asm_scan_first_scan_for_target_writes_no_diff_row() {
        let pool = db_pool().await;
        let tenant = tenant_uuid(TENANT_A);
        let scan_id = seed_pending_scan(&pool, tenant, "first-ever.example").await;
        let script = fake_binary("[]", 0);
        let bin = script.to_str().expect("utf8 path").to_owned();

        let result = run_asm_scan(
            &pool,
            tenant,
            "first-ever.example",
            &serde_json::json!({"scan_id": scan_id}),
            &test_cfg(&bin),
        )
        .await;
        assert_eq!(result.status, "success");

        let diff_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM asm_diffs WHERE scan_id = $1")
                .bind(scan_id)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(diff_count, 0);
    }

    #[tokio::test]
    async fn run_asm_scan_captures_and_uploads_screenshot_for_http_port() {
        let pool = db_pool().await;
        let tenant = tenant_uuid(TENANT_A);
        let scan_id = seed_pending_scan(&pool, tenant, "198.51.100.30").await;

        let masscan = fake_binary(
            r#"[
{ "ip": "198.51.100.30", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] }
]"#,
            0,
        );
        let masscan_bin = masscan.to_str().expect("utf8 path").to_owned();
        let chromium = fake_chromium_binary("fake-png-bytes", 0);
        let chromium_bin = chromium.to_str().expect("utf8 path").to_owned();

        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let uploader =
            ScreenshotUploader::new(mock_s3_client(&server.uri()), "asm-shots".to_owned());
        let cfg = test_cfg_with_screenshot(&masscan_bin, &chromium_bin, uploader);

        let result = run_asm_scan(
            &pool,
            tenant,
            "198.51.100.30",
            &serde_json::json!({"scan_id": scan_id}),
            &cfg,
        )
        .await;
        assert_eq!(result.status, "success");

        let row: (String, String, i32, i32, i32) = sqlx::query_as(
            "SELECT sc.s3_key, sc.tool, sc.width, sc.height, sc.file_size_bytes \
             FROM asm_screenshots sc \
             JOIN asm_services sv ON sv.id = sc.service_id \
             JOIN asm_hosts h ON h.id = sv.host_id \
             WHERE h.scan_id = $1 AND sc.tenant_id = $2",
        )
        .bind(scan_id)
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("screenshot row persisted, tenant-scoped");
        assert!(row.0.starts_with(&format!("asm/{tenant}/{scan_id}/")));
        assert_eq!(row.1, "chromium-headless");
        assert_eq!(row.2, 1280);
        assert_eq!(row.3, 800);
        assert_eq!(row.4, "fake-png-bytes".len() as i32);
    }

    #[tokio::test]
    async fn run_asm_scan_screenshot_capture_failure_for_one_host_does_not_abort_scan() {
        let pool = db_pool().await;
        let tenant = tenant_uuid(TENANT_A);
        let scan_id = seed_pending_scan(&pool, tenant, "198.51.100.31").await;

        let masscan = fake_binary(
            r#"[
{ "ip": "198.51.100.31", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] }
]"#,
            0,
        );
        let masscan_bin = masscan.to_str().expect("utf8 path").to_owned();

        // chromium binary that always fails to spawn — screenshot capture
        // fails for this (only) host, but the scan must still persist the
        // service row and complete successfully.
        let server = MockServer::start().await;
        let uploader =
            ScreenshotUploader::new(mock_s3_client(&server.uri()), "asm-shots".to_owned());
        let cfg = test_cfg_with_screenshot(
            &masscan_bin,
            "/nonexistent/definitely-not-chromium",
            uploader,
        );

        let result = run_asm_scan(
            &pool,
            tenant,
            "198.51.100.31",
            &serde_json::json!({"scan_id": scan_id}),
            &cfg,
        )
        .await;
        assert_eq!(result.status, "success");

        let scan_status: String = sqlx::query_scalar("SELECT status FROM asm_scans WHERE id = $1")
            .bind(scan_id)
            .fetch_one(&pool)
            .await
            .expect("scan row");
        assert_eq!(scan_status, "completed");

        let service_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM asm_services sv JOIN asm_hosts h ON h.id = sv.host_id \
             WHERE h.scan_id = $1 AND sv.tenant_id = $2",
        )
        .bind(scan_id)
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("count services");
        assert_eq!(service_count, 1, "service row still persisted");

        let screenshot_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM asm_screenshots sc \
             JOIN asm_services sv ON sv.id = sc.service_id \
             JOIN asm_hosts h ON h.id = sv.host_id \
             WHERE h.scan_id = $1 AND sc.tenant_id = $2",
        )
        .bind(scan_id)
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("count screenshots");
        assert_eq!(
            screenshot_count, 0,
            "no screenshot row for the failed capture"
        );
    }

    #[tokio::test]
    async fn run_asm_scan_screenshot_upload_failure_for_one_host_does_not_abort_scan() {
        let pool = db_pool().await;
        let tenant = tenant_uuid(TENANT_A);
        let scan_id = seed_pending_scan(&pool, tenant, "198.51.100.32").await;

        let masscan = fake_binary(
            r#"[
{ "ip": "198.51.100.32", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] }
]"#,
            0,
        );
        let masscan_bin = masscan.to_str().expect("utf8 path").to_owned();
        let chromium = fake_chromium_binary("fake-png-bytes", 0);
        let chromium_bin = chromium.to_str().expect("utf8 path").to_owned();

        // Mock S3 server with no mounted route — every PUT 404s, so the
        // capture succeeds but the upload fails.
        let server = MockServer::start().await;
        let uploader =
            ScreenshotUploader::new(mock_s3_client(&server.uri()), "asm-shots".to_owned());
        let cfg = test_cfg_with_screenshot(&masscan_bin, &chromium_bin, uploader);

        let result = run_asm_scan(
            &pool,
            tenant,
            "198.51.100.32",
            &serde_json::json!({"scan_id": scan_id}),
            &cfg,
        )
        .await;
        assert_eq!(result.status, "success");

        let scan_status: String = sqlx::query_scalar("SELECT status FROM asm_scans WHERE id = $1")
            .bind(scan_id)
            .fetch_one(&pool)
            .await
            .expect("scan row");
        assert_eq!(scan_status, "completed");

        let screenshot_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM asm_screenshots sc \
             JOIN asm_services sv ON sv.id = sc.service_id \
             JOIN asm_hosts h ON h.id = sv.host_id \
             WHERE h.scan_id = $1 AND sc.tenant_id = $2",
        )
        .bind(scan_id)
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("count screenshots");
        assert_eq!(
            screenshot_count, 0,
            "no screenshot row for the failed upload"
        );
    }
}
