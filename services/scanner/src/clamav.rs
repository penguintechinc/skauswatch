//! ClamAV `clamd` client speaking `INSTREAM` over TCP, ported from v1's
//! scanner/clamav.py (pyclamd). Streams file bytes to the daemon and maps
//! the reply to malware/PUP verdicts. Absence of a running daemon degrades
//! to "clean" at the call site (matching v1 behavior).

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Chunk size for the `INSTREAM` framing (each chunk is length-prefixed).
const CHUNK: usize = 8192;

/// A ClamAV scan verdict.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClamVerdict {
    /// Any signature matched (malware detected).
    pub is_malware: bool,
    /// The match looks like a PUP/PUA (v1 substring heuristic).
    pub is_pup: bool,
    /// Signature names reported by the daemon.
    pub threat_names: Vec<String>,
}

/// Errors from the clamd transport or an `ERROR` reply.
#[derive(Debug, thiserror::Error)]
pub enum ClamError {
    /// TCP connect/read/write failure.
    #[error("clamd io error: {0}")]
    Io(#[from] std::io::Error),
    /// The scan timed out.
    #[error("clamd scan timed out")]
    Timeout,
    /// clamd returned an `ERROR` reply.
    #[error("clamd error reply: {0}")]
    Reply(String),
    /// The reply could not be understood.
    #[error("unparseable clamd reply: {0:?}")]
    Unparseable(String),
}

/// Streams `data` to clamd at `host:port` and returns the verdict.
///
/// # Errors
/// Returns [`ClamError`] on transport failure, timeout, or an `ERROR` reply.
/// A daemon that is simply down surfaces as [`ClamError::Io`]; callers treat
/// that as "scanning unavailable" rather than a threat.
pub async fn scan_bytes(
    host: &str,
    port: u16,
    timeout: Duration,
    data: &[u8],
) -> Result<ClamVerdict, ClamError> {
    let fut = scan_inner(host, port, data);
    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(ClamError::Timeout),
    }
}

/// Connects, runs `INSTREAM`, and parses the reply.
async fn scan_inner(host: &str, port: u16, data: &[u8]) -> Result<ClamVerdict, ClamError> {
    let mut stream = TcpStream::connect((host, port)).await?;
    // 'z' prefix ⇒ null-terminated command; the reply is null-terminated too.
    stream.write_all(b"zINSTREAM\0").await?;
    for chunk in data.chunks(CHUNK) {
        let len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(chunk).await?;
    }
    // Zero-length chunk terminates the stream.
    stream.write_all(&0u32.to_be_bytes()).await?;
    stream.flush().await?;

    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await?;
    let text = String::from_utf8_lossy(&reply);
    parse_clamav_response(text.trim_matches(|c| c == '\0' || c == '\n' || c == ' '))
}

/// Parses a single `INSTREAM` reply line into a verdict.
///
/// - `stream: OK` ⇒ clean.
/// - `stream: <Sig> FOUND` ⇒ malware (`PUP`/`PUA` in the name ⇒ PUP).
/// - `... ERROR` ⇒ [`ClamError::Reply`].
pub fn parse_clamav_response(line: &str) -> Result<ClamVerdict, ClamError> {
    let line = line.trim();
    if line.ends_with("ERROR") {
        return Err(ClamError::Reply(line.to_owned()));
    }
    if line.ends_with("OK") {
        return Ok(ClamVerdict::default());
    }
    if let Some(rest) = line.strip_suffix(" FOUND") {
        // "stream: <signature>" → take everything after the first ": ".
        let sig = rest.split_once(": ").map_or(rest, |(_, s)| s).trim();
        let is_pup = sig.contains("PUP") || sig.contains("PUA");
        return Ok(ClamVerdict {
            is_malware: true,
            is_pup,
            threat_names: vec![sig.to_owned()],
        });
    }
    Err(ClamError::Unparseable(line.to_owned()))
}

/// Spawns a minimal fake `clamd` on an ephemeral loopback port that reads a
/// full `INSTREAM` frame (header, length-prefixed chunks, zero-length
/// terminator) then writes back `reply` verbatim and closes. Test-only.
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)] // test-only: fail loudly by design
pub(crate) async fn spawn_fake_clamd(reply: &'static [u8]) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind fake clamd: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("fake clamd local_addr: {e}"));
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            // "zINSTREAM\0" header.
            let mut header = [0u8; 10];
            if sock.read_exact(&mut header).await.is_err() {
                return;
            }
            loop {
                let mut len_buf = [0u8; 4];
                if sock.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes(len_buf);
                if len == 0 {
                    break;
                }
                let mut chunk = vec![0u8; len as usize];
                if sock.read_exact(&mut chunk).await.is_err() {
                    break;
                }
            }
            let _ = sock.write_all(reply).await;
            let _ = sock.shutdown().await;
        }
    });
    addr
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)] // tests fail loudly by design
mod tests {
    use super::*;

    #[tokio::test]
    async fn scan_bytes_round_trip_clean_verdict() {
        let addr = spawn_fake_clamd(b"stream: OK\0").await;
        let verdict = scan_bytes(
            &addr.ip().to_string(),
            addr.port(),
            Duration::from_secs(2),
            b"hello world, nothing malicious",
        )
        .await
        .expect("scan succeeds against fake clamd");
        assert_eq!(verdict, ClamVerdict::default());
    }

    #[tokio::test]
    async fn scan_bytes_round_trip_found_verdict() {
        let addr = spawn_fake_clamd(b"stream: Win.Test.EICAR_HDB-1 FOUND\0").await;
        const EICAR: &[u8] =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let verdict = scan_bytes(
            &addr.ip().to_string(),
            addr.port(),
            Duration::from_secs(2),
            EICAR,
        )
        .await
        .expect("scan succeeds against fake clamd");
        assert!(verdict.is_malware);
        assert!(!verdict.is_pup);
        assert_eq!(
            verdict.threat_names,
            vec!["Win.Test.EICAR_HDB-1".to_owned()]
        );
    }

    #[tokio::test]
    async fn scan_bytes_round_trip_error_reply_is_err() {
        let addr = spawn_fake_clamd(b"INSTREAM size limit exceeded ERROR\0").await;
        let result = scan_bytes(
            &addr.ip().to_string(),
            addr.port(),
            Duration::from_secs(2),
            b"x",
        )
        .await;
        assert!(matches!(result, Err(ClamError::Reply(_))));
    }

    #[tokio::test]
    async fn scan_bytes_multi_chunk_payload_round_trips() {
        // Payload spans multiple CHUNK-sized frames — exercises the
        // chunking loop in `scan_inner`, not just the single-chunk path.
        let addr = spawn_fake_clamd(b"stream: OK\0").await;
        let data = vec![0x41u8; CHUNK * 2 + 17];
        let verdict = scan_bytes(
            &addr.ip().to_string(),
            addr.port(),
            Duration::from_secs(2),
            &data,
        )
        .await
        .expect("scan succeeds against fake clamd");
        assert_eq!(verdict, ClamVerdict::default());
    }

    #[tokio::test]
    async fn scan_bytes_dead_port_is_io_error() {
        // Nothing listens on 127.0.0.1:1 (a privileged port) in the test
        // environment — connection is refused immediately, exercising the
        // "clamd daemon simply down" transport-failure path.
        let result = scan_bytes("127.0.0.1", 1, Duration::from_millis(500), b"data").await;
        assert!(matches!(result, Err(ClamError::Io(_))));
    }

    #[test]
    fn clean_reply() {
        assert_eq!(
            parse_clamav_response("stream: OK").expect("ok"),
            ClamVerdict::default()
        );
    }

    #[test]
    fn found_reply_extracts_signature() {
        let v = parse_clamav_response("stream: Win.Test.EICAR_HDB-1 FOUND").expect("found");
        assert!(v.is_malware);
        assert!(!v.is_pup);
        assert_eq!(v.threat_names, vec!["Win.Test.EICAR_HDB-1".to_owned()]);
    }

    #[test]
    fn pup_signature_flags_pup() {
        let v = parse_clamav_response("stream: PUA.Win.Tool.Xyz FOUND").expect("found");
        assert!(v.is_malware);
        assert!(v.is_pup);
    }

    #[test]
    fn error_reply_is_err() {
        assert!(matches!(
            parse_clamav_response("INSTREAM size limit exceeded ERROR"),
            Err(ClamError::Reply(_))
        ));
    }

    #[test]
    fn garbage_reply_is_unparseable() {
        assert!(matches!(
            parse_clamav_response("what"),
            Err(ClamError::Unparseable(_))
        ));
    }
}
