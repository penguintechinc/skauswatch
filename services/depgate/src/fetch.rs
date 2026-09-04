//! Shared size-capped HTTP GET used by the npm/PyPI upstream clients
//! (`src/npm.rs`, `src/pypi.rs`). Same streaming-cap technique as
//! `src/upstream.rs::UpstreamClient::read_body` (stream rather than
//! buffer-then-check, so an upstream that lies about or omits
//! `Content-Length` still can't force an unbounded in-memory buffer) —
//! extracted here rather than added to `upstream.rs` itself so P1's
//! already-covered OCI client stays untouched; npm and PyPI have no
//! Bearer-challenge dance to reuse from it, only this streaming-cap shape.

use bytes::Bytes;
use futures::StreamExt;

/// Failures from a capped upstream GET.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// Transport-level failure (DNS, TLS, connect, timeout).
    #[error("upstream request failed: {0}")]
    Request(String),
    /// Upstream answered with a non-success, non-404 status.
    #[error("upstream returned {status}")]
    Status {
        /// HTTP status code.
        status: u16,
    },
    /// The requested resource does not exist upstream.
    #[error("not found upstream")]
    NotFound,
    /// The response body exceeded the configured size guard.
    #[error("artifact exceeds max size ({0} bytes)")]
    TooLarge(u64),
}

/// A fetched, not-yet-scanned body plus its `Content-Type`.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// Raw response bytes.
    pub bytes: Bytes,
    /// `Content-Type` header from the response (defaults to
    /// `application/octet-stream` when absent).
    pub content_type: String,
}

/// Sends `req`, streaming the body under `max_bytes`.
///
/// # Errors
/// See [`FetchError`].
pub async fn get_capped(
    req: reqwest::RequestBuilder,
    max_bytes: u64,
) -> Result<Fetched, FetchError> {
    let resp = req
        .send()
        .await
        .map_err(|e| FetchError::Request(e.to_string()))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(FetchError::NotFound);
    }
    if !status.is_success() {
        return Err(FetchError::Status {
            status: status.as_u16(),
        });
    }
    if let Some(len) = resp.content_length()
        && len > max_bytes
    {
        return Err(FetchError::TooLarge(len));
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();

    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| FetchError::Request(e.to_string()))?;
        buf.extend_from_slice(&chunk);
        if buf.len() as u64 > max_bytes {
            return Err(FetchError::TooLarge(buf.len() as u64));
        }
    }
    Ok(Fetched {
        bytes: Bytes::from(buf),
        content_type,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[tokio::test]
    async fn get_capped_returns_bytes_and_content_type_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ok"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_bytes(b"{}".to_vec()),
            )
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let got = get_capped(client.get(format!("{}/ok", server.uri())), 1024)
            .await
            .expect("fetch");
        assert_eq!(got.bytes.as_ref(), b"{}");
        assert_eq!(got.content_type, "application/json");
    }

    #[tokio::test]
    async fn get_capped_maps_404_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = get_capped(client.get(format!("{}/missing", server.uri())), 1024)
            .await
            .expect_err("expected not found");
        assert!(matches!(err, FetchError::NotFound));
    }

    #[tokio::test]
    async fn get_capped_maps_other_error_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/boom"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = get_capped(client.get(format!("{}/boom", server.uri())), 1024)
            .await
            .expect_err("expected status error");
        assert!(matches!(err, FetchError::Status { status: 500 }));
    }

    #[tokio::test]
    async fn get_capped_rejects_oversized_content_length() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(vec![0u8; 2048], "text/plain"))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = get_capped(client.get(format!("{}/big", server.uri())), 1024)
            .await
            .expect_err("expected too large");
        assert!(matches!(err, FetchError::TooLarge(2048)));
    }
}
