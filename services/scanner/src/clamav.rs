//! Test-only fixture for `scan.rs`'s ClamAV branch tests. The actual
//! `clamd` INSTREAM/TCP protocol implementation moved to
//! `skauswatch-scan-core::clamav` (shared with `s3scan`, which speaks the
//! same protocol over a Unix socket instead) — see
//! `docs/v2-port/v2.1-depgate.md` §3. That crate's own test suite already
//! covers `scan_bytes`/`parse_clamav_response` over both transports; this
//! file keeps only the fake-`clamd` TCP server `scan.rs`'s tests dial into.

/// Spawns a minimal fake `clamd` on an ephemeral loopback port that reads a
/// full `INSTREAM` frame (header, length-prefixed chunks, zero-length
/// terminator) then writes back `reply` verbatim and closes. Test-only.
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)] // test-only: fail loudly by design
pub(crate) async fn spawn_fake_clamd(reply: &'static [u8]) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
