//! Minimal ClamAV `clamd` client speaking `INSTREAM` over a Unix socket, a
//! direct port of what v1 `scanner/clamav.py` (pyclamd) did: stream the file
//! bytes to the daemon and map the reply to malware/PUP verdicts. Absence of a
//! running daemon degrades to "clean" at the call site (matching v1, which
//! set `clamav_scanner = None` and skipped scanning when clamd was down).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Chunk size for the `INSTREAM` framing (each chunk is length-prefixed).
const CHUNK: usize = 8192;

/// A ClamAV scan verdict.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClamVerdict {
    /// Any signature matched.
    pub is_malware: bool,
    /// The match looks like a PUP/PUA (v1 substring heuristic).
    pub is_pup: bool,
    /// Signature names reported by the daemon.
    pub threat_names: Vec<String>,
}

/// Errors from the clamd transport or an `ERROR` reply.
#[derive(Debug, thiserror::Error)]
pub enum ClamError {
    /// Socket connect/read/write failure.
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

/// Streams `data` to clamd at `socket_path` and returns the verdict.
///
/// # Errors
/// Returns [`ClamError`] on transport failure, timeout, or an `ERROR` reply.
/// A daemon that is simply down surfaces as [`ClamError::Io`]; callers treat
/// that as "scanning unavailable" rather than a threat.
pub async fn scan_bytes(
    socket_path: &str,
    timeout: Duration,
    data: &[u8],
) -> Result<ClamVerdict, ClamError> {
    let fut = scan_inner(socket_path, data);
    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(ClamError::Timeout),
    }
}

/// Connects, runs `INSTREAM`, and parses the reply.
async fn scan_inner(socket_path: &str, data: &[u8]) -> Result<ClamVerdict, ClamError> {
    let mut stream = UnixStream::connect(socket_path).await?;
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

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)] // tests fail loudly by design
mod tests {
    use super::*;

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

    // ── scan_bytes() — real Unix-socket transport ───────────────────────────
    //
    // A fake clamd: accepts one connection, drains the `INSTREAM` framing
    // (the `zINSTREAM\0` command, each length-prefixed chunk, the zero-length
    // terminator), then writes back a fixed reply. Good enough to exercise
    // the real wire protocol `scan_inner` speaks without a real ClamAV
    // daemon.

    use tokio::net::UnixListener;

    fn unique_socket_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("s3scan-clamd-test-{}.sock", uuid::Uuid::new_v4()))
    }

    /// Binds a listener, accepts one connection, drains the INSTREAM frames,
    /// then runs `on_drained` (write a reply, or hang, or close immediately).
    fn spawn_fake_clamd<F, Fut>(path: std::path::PathBuf, on_drained: F)
    where
        F: FnOnce(UnixStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = UnixListener::bind(&path).expect("bind fake clamd socket");
        tokio::spawn(async move {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            // "zINSTREAM\0" command.
            let mut cmd = [0u8; 10];
            if stream.read_exact(&mut cmd).await.is_err() {
                return;
            }
            loop {
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u32::from_be_bytes(len_buf);
                if len == 0 {
                    break;
                }
                let mut chunk = vec![0u8; len as usize];
                if stream.read_exact(&mut chunk).await.is_err() {
                    return;
                }
            }
            on_drained(stream).await;
        });
    }

    #[tokio::test]
    async fn unreachable_socket_is_io_error() {
        let err = scan_bytes(
            "/nonexistent/s3scan-clamd.sock",
            Duration::from_secs(2),
            b"data",
        )
        .await
        .expect_err("expected io error");
        assert!(matches!(err, ClamError::Io(_)));
    }

    #[tokio::test]
    async fn clean_reply_over_real_socket() {
        let path = unique_socket_path();
        spawn_fake_clamd(path.clone(), |mut stream| async move {
            let _ = stream.write_all(b"stream: OK\0").await;
            let _ = stream.flush().await;
        });
        tokio::task::yield_now().await;

        let v = scan_bytes(
            path.to_str().expect("utf8 path"),
            Duration::from_secs(5),
            b"hello",
        )
        .await
        .expect("scan");
        assert_eq!(v, ClamVerdict::default());
    }

    #[tokio::test]
    async fn malware_reply_over_real_socket_multi_chunk_payload() {
        let path = unique_socket_path();
        spawn_fake_clamd(path.clone(), |mut stream| async move {
            let _ = stream
                .write_all(b"stream: Win.Test.EICAR_HDB-1 FOUND\0")
                .await;
            let _ = stream.flush().await;
        });
        tokio::task::yield_now().await;

        // Larger than CHUNK (8192) so the write loop spans multiple frames.
        let payload = vec![0x41u8; CHUNK * 2 + 37];
        let v = scan_bytes(
            path.to_str().expect("utf8 path"),
            Duration::from_secs(5),
            &payload,
        )
        .await
        .expect("scan");
        assert!(v.is_malware);
        assert_eq!(v.threat_names, vec!["Win.Test.EICAR_HDB-1".to_owned()]);
    }

    #[tokio::test]
    async fn error_reply_over_real_socket() {
        let path = unique_socket_path();
        spawn_fake_clamd(path.clone(), |mut stream| async move {
            let _ = stream
                .write_all(b"INSTREAM size limit exceeded ERROR\0")
                .await;
            let _ = stream.flush().await;
        });
        tokio::task::yield_now().await;

        let err = scan_bytes(
            path.to_str().expect("utf8 path"),
            Duration::from_secs(5),
            b"x",
        )
        .await
        .expect_err("expected reply error");
        assert!(matches!(err, ClamError::Reply(_)));
    }

    #[tokio::test]
    async fn unparseable_reply_over_real_socket() {
        let path = unique_socket_path();
        spawn_fake_clamd(path.clone(), |mut stream| async move {
            let _ = stream.write_all(b"gibberish\0").await;
            let _ = stream.flush().await;
        });
        tokio::task::yield_now().await;

        let err = scan_bytes(
            path.to_str().expect("utf8 path"),
            Duration::from_secs(5),
            b"x",
        )
        .await
        .expect_err("expected unparseable error");
        assert!(matches!(err, ClamError::Unparseable(_)));
    }

    #[tokio::test]
    async fn scan_times_out_when_daemon_never_replies() {
        let path = unique_socket_path();
        spawn_fake_clamd(path.clone(), |stream| async move {
            // Keep `stream` alive (an unused/underscore-bound parameter would
            // be dropped — and the connection closed — before this async
            // block ever runs) then hang forever without replying, so
            // `scan_bytes`'s outer `tokio::time::timeout` must win.
            let _keep_alive = stream;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;

        let err = scan_bytes(
            path.to_str().expect("utf8 path"),
            Duration::from_millis(200),
            b"x",
        )
        .await
        .expect_err("expected timeout");
        assert!(matches!(err, ClamError::Timeout));
    }
}
