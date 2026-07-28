//! S3/MinIO operations for the scan pipeline, ported from v1 `s3/` (client,
//! downloader, tagger). Per-object work builds an `aws-sdk-s3` client from the
//! stored bucket credentials (mirroring the manager's connection-test path),
//! enumerates with pagination + prefix, downloads with a size guard, and
//! writes result tags best-effort.

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};

/// Metadata for one enumerated object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    /// Object key.
    pub key: String,
    /// Size in bytes (0 when the listing omits it).
    pub size: i64,
    /// ETag (empty when absent).
    pub etag: String,
}

/// Builds an S3 client from explicit credentials (bucket config or inline
/// task). `endpoint_url` targets MinIO/S3-compatible stores; `path_style`
/// follows the stored config.
pub fn client_from_credentials(
    endpoint_url: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    path_style: bool,
) -> Client {
    let creds = Credentials::new(access_key, secret_key, None, None, "s3scan");
    let cfg = aws_sdk_s3::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region.to_owned()))
        .endpoint_url(endpoint_url)
        .force_path_style(path_style)
        .credentials_provider(creds)
        .build();
    Client::from_conf(cfg)
}

/// Lists every object under `prefix` (all pages) via `ListObjectsV2`.
///
/// # Errors
/// Returns an error string on any S3 failure.
pub async fn list_all_objects(
    client: &Client,
    bucket: &str,
    prefix: Option<&str>,
) -> Result<Vec<ObjectMeta>, String> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut req = client.list_objects_v2().bucket(bucket);
        if let Some(p) = prefix
            && !p.is_empty()
        {
            req = req.prefix(p);
        }
        if let Some(t) = &token {
            req = req.continuation_token(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("list_objects_v2: {e}"))?;
        for obj in resp.contents() {
            if let Some(key) = obj.key() {
                out.push(ObjectMeta {
                    key: key.to_owned(),
                    size: obj.size().unwrap_or(0),
                    etag: obj.e_tag().unwrap_or_default().to_owned(),
                });
            }
        }
        if resp.is_truncated().unwrap_or(false) {
            token = resp.next_continuation_token().map(str::to_owned);
            if token.is_none() {
                break;
            }
        } else {
            break;
        }
    }
    Ok(out)
}

/// Downloads an object into memory, enforcing `max_bytes`. Returns `Ok(None)`
/// when the object exceeds the limit (the v1 "skip too large" outcome).
///
/// # Errors
/// Returns an error string on transport/read failure.
pub async fn download_object(
    client: &Client,
    bucket: &str,
    key: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, String> {
    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .map_err(|e| format!("get_object: {e}"))?;
    if let Some(len) = resp.content_length()
        && (len < 0 || len as u64 > max_bytes)
    {
        return Ok(None);
    }
    let data = resp
        .body
        .collect()
        .await
        .map_err(|e| format!("read body: {e}"))?
        .into_bytes();
    if data.len() as u64 > max_bytes {
        return Ok(None);
    }
    Ok(Some(data.to_vec()))
}

/// Writes scan-result tags, returning `false` on any failure (best-effort, as
/// v1 `S3Tagger` swallowed errors).
pub async fn put_object_tags(
    client: &Client,
    bucket: &str,
    key: &str,
    tags: &[(String, String)],
) -> bool {
    let mut set = Vec::with_capacity(tags.len());
    for (k, v) in tags {
        match aws_sdk_s3::types::Tag::builder().key(k).value(v).build() {
            Ok(t) => set.push(t),
            Err(_) => return false,
        }
    }
    let tagging = match aws_sdk_s3::types::Tagging::builder()
        .set_tag_set(Some(set))
        .build()
    {
        Ok(t) => t,
        Err(_) => return false,
    };
    client
        .put_object_tagging()
        .bucket(bucket)
        .key(key)
        .tagging(tagging)
        .send()
        .await
        .is_ok()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)] // tests fail loudly by design
mod tests {
    use wiremock::matchers::{method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// Builds a client pointed at a mock server, matching how `handler.rs`
    /// builds clients from stored bucket credentials / inline task creds.
    fn mock_client(uri: &str) -> Client {
        client_from_credentials(uri, "AKTEST", "SKTEST", "us-east-1", true)
    }

    fn contents_xml(key: &str, size: i64, etag: &str) -> String {
        format!(
            "<Contents><Key>{key}</Key><LastModified>2024-01-01T00:00:00.000Z</LastModified>\
             <ETag>&quot;{etag}&quot;</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>"
        )
    }

    fn list_bucket_result(
        bucket: &str,
        contents: &str,
        truncated: bool,
        next_token: Option<&str>,
    ) -> String {
        let next = next_token
            .map(|t| format!("<NextContinuationToken>{t}</NextContinuationToken>"))
            .unwrap_or_default();
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>{bucket}</Name><Prefix></Prefix><MaxKeys>1000</MaxKeys>\
             <IsTruncated>{truncated}</IsTruncated>{contents}{next}</ListBucketResult>"
        )
    }

    fn s3_error_xml(code: &str, message: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{code}</Code><Message>{message}</Message>\
             <RequestId>req-1</RequestId><HostId>host-1</HostId></Error>"
        )
    }

    #[tokio::test]
    async fn list_all_objects_empty_bucket() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/empty-bucket/"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                list_bucket_result("empty-bucket", "", false, None),
                "application/xml",
            ))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let got = list_all_objects(&client, "empty-bucket", None)
            .await
            .expect("list");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn list_all_objects_maps_key_size_and_etag() {
        let server = MockServer::start().await;
        let contents = contents_xml("uploads/a.bin", 1024, "abc123");
        Mock::given(method("GET"))
            .and(path("/bkt/"))
            .and(query_param_is_missing("prefix"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                list_bucket_result("bkt", &contents, false, None),
                "application/xml",
            ))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let got = list_all_objects(&client, "bkt", None).await.expect("list");
        assert_eq!(
            got,
            vec![ObjectMeta {
                key: "uploads/a.bin".to_owned(),
                size: 1024,
                etag: "\"abc123\"".to_owned(),
            }]
        );
    }

    #[tokio::test]
    async fn list_all_objects_sends_nonempty_prefix() {
        let server = MockServer::start().await;
        let contents = contents_xml("uploads/a.bin", 10, "e1");
        Mock::given(method("GET"))
            .and(path("/bkt/"))
            .and(query_param("prefix", "uploads/"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                list_bucket_result("bkt", &contents, false, None),
                "application/xml",
            ))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let got = list_all_objects(&client, "bkt", Some("uploads/"))
            .await
            .expect("list");
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn list_all_objects_follows_pagination() {
        let server = MockServer::start().await;
        let page1 = contents_xml("a.bin", 1, "e1");
        let page2 = contents_xml("b.bin", 2, "e2");
        // First request (no continuation-token) — truncated, hands back a token.
        Mock::given(method("GET"))
            .and(path("/bkt/"))
            .and(query_param_is_missing("continuation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                list_bucket_result("bkt", &page1, true, Some("tok-1")),
                "application/xml",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Second request carries the token — final page.
        Mock::given(method("GET"))
            .and(path("/bkt/"))
            .and(query_param("continuation-token", "tok-1"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                list_bucket_result("bkt", &page2, false, None),
                "application/xml",
            ))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let got = list_all_objects(&client, "bkt", None).await.expect("list");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].key, "a.bin");
        assert_eq!(got[1].key, "b.bin");
    }

    #[tokio::test]
    async fn list_all_objects_propagates_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bkt/"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_raw(s3_error_xml("InternalError", "boom"), "application/xml"),
            )
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let err = list_all_objects(&client, "bkt", None)
            .await
            .expect_err("expected error");
        assert!(err.contains("list_objects_v2"));
    }

    #[tokio::test]
    async fn download_object_returns_bytes_within_limit() {
        let server = MockServer::start().await;
        let body = b"hello world".to_vec();
        Mock::given(method("GET"))
            .and(path("/bkt/uploads/a.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let got = download_object(&client, "bkt", "uploads/a.bin", 1024)
            .await
            .expect("download")
            .expect("bytes present");
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn download_object_skips_when_content_length_exceeds_max() {
        let server = MockServer::start().await;
        let body = vec![0u8; 2048];
        Mock::given(method("GET"))
            .and(path("/bkt/big.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let got = download_object(&client, "bkt", "big.bin", 1024)
            .await
            .expect("download");
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn download_object_propagates_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bkt/missing.bin"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_raw(s3_error_xml("NoSuchKey", "not found"), "application/xml"),
            )
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let err = download_object(&client, "bkt", "missing.bin", 1024)
            .await
            .expect_err("expected error");
        assert!(err.contains("get_object"));
    }

    #[tokio::test]
    async fn put_object_tags_succeeds_on_2xx() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/bkt/a.bin"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let tags = vec![("malware".to_owned(), "false".to_owned())];
        assert!(put_object_tags(&client, "bkt", "a.bin", &tags).await);
    }

    #[tokio::test]
    async fn put_object_tags_returns_false_on_http_failure() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/bkt/a.bin"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_raw(s3_error_xml("InternalError", "boom"), "application/xml"),
            )
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let tags = vec![("malware".to_owned(), "false".to_owned())];
        assert!(!put_object_tags(&client, "bkt", "a.bin", &tags).await);
    }
}
