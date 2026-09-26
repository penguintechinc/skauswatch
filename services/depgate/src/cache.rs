//! Content-addressed S3/MinIO cache operations — the "verdict-as-object-tag"
//! half of `docs/v2-port/v2.1-depgate.md` §2. Every servable object is keyed
//! by `{cache_prefix}{sha256_hex}` (default `sha256/<hex>`); every flagged
//! object goes to `{quarantine_prefix}{sha256_hex}` instead and is never
//! read by the serve path. Automatic dedup falls out of the key scheme
//! itself: two requests for the same bytes always resolve to the same key,
//! so `put_object` on an already-cached digest is simply a harmless
//! overwrite with identical content, never a second scan.
//!
//! Local to this service (not `skauswatch-s3`), matching
//! `services/s3scan/src/s3ops.rs`'s precedent — each consumer's S3
//! call-shape differs enough (tag-only reads before a body fetch here; v1
//! `S3Tagger`/`downloader` parity there) that a shared abstraction would
//! just be an extra indirection layer, not less code.

use aws_sdk_s3::Client;
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;

/// Cache/quarantine object operations failures. Distinct from "object not
/// found", which is `Ok(None)` — these represent a genuine S3/transport
/// failure the caller must handle (typically as a 500, never silently
/// treated as a cache miss).
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// `GetObject` failed for a reason other than "key not found".
    #[error("s3 get_object failed: {0}")]
    Get(String),
    /// `GetObjectTagging` failed for a reason other than "key not found".
    #[error("s3 get_object_tagging failed: {0}")]
    GetTagging(String),
    /// `PutObject` failed.
    #[error("s3 put_object failed: {0}")]
    Put(String),
    /// `PutObjectTagging` failed, or the tag set itself was malformed.
    #[error("s3 put_object_tagging failed: {0}")]
    PutTagging(String),
}

/// A cached object's bytes plus its stored `Content-Type` — set explicitly
/// at [`put_object`] time from whatever upstream returned, so re-serving a
/// cached manifest/blob preserves its original media type.
#[derive(Debug, Clone)]
pub struct CachedObject {
    /// Object bytes.
    pub bytes: Bytes,
    /// Stored `Content-Type`.
    pub content_type: String,
}

/// Builds the content-addressed key for `sha256_hex` under `prefix`
/// (`cache_prefix` or `quarantine_prefix`, both configured to end in `/`).
#[must_use]
pub fn object_key(prefix: &str, sha256_hex: &str) -> String {
    format!("{prefix}{sha256_hex}")
}

/// True when `err` is exactly "no such key" — every other S3 error is a
/// real failure, not a cache miss. Generic over the AWS SDK's per-operation
/// error type so one helper covers `GetObject`/`GetObjectTagging`.
fn is_not_found<E, R>(err: &aws_sdk_s3::error::SdkError<E, R>) -> bool
where
    E: ProvideErrorMetadata,
{
    err.as_service_error()
        .and_then(ProvideErrorMetadata::code)
        .is_some_and(|c| c == "NoSuchKey")
}

/// Reads the tag set of `key`, the "read the verdict off the object" step
/// on the hot serve path — no DB round-trip. `Ok(None)` means the key
/// doesn't exist (cache miss); any other error is a genuine S3 failure.
///
/// # Errors
/// See [`CacheError::GetTagging`].
pub async fn get_tags(
    client: &Client,
    bucket: &str,
    key: &str,
) -> Result<Option<Vec<(String, String)>>, CacheError> {
    match client
        .get_object_tagging()
        .bucket(bucket)
        .key(key)
        .send()
        .await
    {
        Ok(resp) => Ok(Some(
            resp.tag_set()
                .iter()
                .map(|t| (t.key().to_owned(), t.value().to_owned()))
                .collect(),
        )),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(CacheError::GetTagging(e.to_string())),
    }
}

/// Fetches `key`'s bytes and stored content type. `Ok(None)` on a cache
/// miss.
///
/// # Errors
/// See [`CacheError::Get`].
pub async fn get_object(
    client: &Client,
    bucket: &str,
    key: &str,
) -> Result<Option<CachedObject>, CacheError> {
    match client.get_object().bucket(bucket).key(key).send().await {
        Ok(resp) => {
            let content_type = resp
                .content_type()
                .unwrap_or("application/octet-stream")
                .to_owned();
            let data = resp
                .body
                .collect()
                .await
                .map_err(|e| CacheError::Get(e.to_string()))?
                .into_bytes();
            Ok(Some(CachedObject {
                bytes: data,
                content_type,
            }))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(CacheError::Get(e.to_string())),
    }
}

/// Writes `bytes` to `key` with the given `content_type`. Overwriting an
/// existing key with identical content (the dedup case) is a harmless no-op
/// from the caller's perspective.
///
/// # Errors
/// See [`CacheError::Put`].
pub async fn put_object(
    client: &Client,
    bucket: &str,
    key: &str,
    bytes: Bytes,
    content_type: &str,
) -> Result<(), CacheError> {
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(bytes))
        .content_type(content_type)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| CacheError::Put(e.to_string()))
}

/// Writes `tags` (the scan-core `verdict_tags(...)` output) onto `key`.
///
/// # Errors
/// See [`CacheError::PutTagging`].
pub async fn put_tags(
    client: &Client,
    bucket: &str,
    key: &str,
    tags: &[(String, String)],
) -> Result<(), CacheError> {
    let mut set = Vec::with_capacity(tags.len());
    for (k, v) in tags {
        let tag = aws_sdk_s3::types::Tag::builder()
            .key(k)
            .value(v)
            .build()
            .map_err(|e| CacheError::PutTagging(e.to_string()))?;
        set.push(tag);
    }
    let tagging = aws_sdk_s3::types::Tagging::builder()
        .set_tag_set(Some(set))
        .build()
        .map_err(|e| CacheError::PutTagging(e.to_string()))?;
    client
        .put_object_tagging()
        .bucket(bucket)
        .key(key)
        .tagging(tagging)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| CacheError::PutTagging(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)] // tests fail loudly by design
mod tests {
    use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn mock_client(uri: &str) -> Client {
        let creds = Credentials::new("AKTEST", "SKTEST", None, None, "depgate-test");
        let cfg = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(uri)
            .force_path_style(true)
            .credentials_provider(creds)
            .build();
        Client::from_conf(cfg)
    }

    fn s3_error_xml(code: &str, message: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{code}</Code><Message>{message}</Message>\
             <RequestId>req-1</RequestId><HostId>host-1</HostId></Error>"
        )
    }

    #[test]
    fn object_key_joins_prefix_and_hash() {
        assert_eq!(object_key("sha256/", "abc123"), "sha256/abc123");
        assert_eq!(object_key("quarantine/", "abc123"), "quarantine/abc123");
    }

    #[tokio::test]
    async fn get_tags_returns_none_on_no_such_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bkt/sha256/missing"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_raw(s3_error_xml("NoSuchKey", "not found"), "application/xml"),
            )
            .mount(&server)
            .await;

        let got = get_tags(&mock_client(&server.uri()), "bkt", "sha256/missing")
            .await
            .expect("no error");
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn get_tags_returns_tag_set_on_hit() {
        let server = MockServer::start().await;
        let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Tagging><TagSet><Tag><Key>threat</Key><Value>clean</Value></Tag></TagSet></Tagging>";
        Mock::given(method("GET"))
            .and(path("/bkt/sha256/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/xml"))
            .mount(&server)
            .await;

        let got = get_tags(&mock_client(&server.uri()), "bkt", "sha256/abc")
            .await
            .expect("no error")
            .expect("tags present");
        assert_eq!(got, vec![("threat".to_owned(), "clean".to_owned())]);
    }

    #[tokio::test]
    async fn get_tags_propagates_real_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bkt/sha256/abc"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_raw(s3_error_xml("InternalError", "boom"), "application/xml"),
            )
            .mount(&server)
            .await;

        let err = get_tags(&mock_client(&server.uri()), "bkt", "sha256/abc")
            .await
            .expect_err("expected error");
        assert!(matches!(err, CacheError::GetTagging(_)));
    }

    #[tokio::test]
    async fn get_object_returns_none_on_miss() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bkt/sha256/missing"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_raw(s3_error_xml("NoSuchKey", "not found"), "application/xml"),
            )
            .mount(&server)
            .await;

        let got = get_object(&mock_client(&server.uri()), "bkt", "sha256/missing")
            .await
            .expect("no error");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn get_object_returns_bytes_and_content_type_on_hit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bkt/sha256/abc"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                    .set_body_bytes(b"{}".to_vec()),
            )
            .mount(&server)
            .await;

        let got = get_object(&mock_client(&server.uri()), "bkt", "sha256/abc")
            .await
            .expect("no error")
            .expect("object present");
        assert_eq!(got.bytes.as_ref(), b"{}");
        assert_eq!(
            got.content_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
    }

    #[tokio::test]
    async fn put_object_succeeds_on_2xx() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/bkt/sha256/abc"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        put_object(
            &mock_client(&server.uri()),
            "bkt",
            "sha256/abc",
            Bytes::from_static(b"hello"),
            "application/octet-stream",
        )
        .await
        .expect("put succeeds");
    }

    #[tokio::test]
    async fn put_object_propagates_failure() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/bkt/sha256/abc"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_raw(s3_error_xml("InternalError", "boom"), "application/xml"),
            )
            .mount(&server)
            .await;

        let err = put_object(
            &mock_client(&server.uri()),
            "bkt",
            "sha256/abc",
            Bytes::from_static(b"hello"),
            "application/octet-stream",
        )
        .await
        .expect_err("expected error");
        assert!(matches!(err, CacheError::Put(_)));
    }

    #[tokio::test]
    async fn put_tags_succeeds_on_2xx() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/bkt/sha256/abc"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        put_tags(
            &mock_client(&server.uri()),
            "bkt",
            "sha256/abc",
            &[("threat".to_owned(), "clean".to_owned())],
        )
        .await
        .expect("put_tags succeeds");
    }

    #[tokio::test]
    async fn put_tags_propagates_failure() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/bkt/sha256/abc"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_raw(s3_error_xml("InternalError", "boom"), "application/xml"),
            )
            .mount(&server)
            .await;

        let err = put_tags(
            &mock_client(&server.uri()),
            "bkt",
            "sha256/abc",
            &[("threat".to_owned(), "clean".to_owned())],
        )
        .await
        .expect_err("expected error");
        assert!(matches!(err, CacheError::PutTagging(_)));
    }
}
