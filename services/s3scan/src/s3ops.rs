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
