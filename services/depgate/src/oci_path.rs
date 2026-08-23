//! Pure OCI Distribution path parsing. Axum's wildcard route captures the
//! full `{name}/...` remainder of a `/v2/` request as a single segment (the
//! OCI spec's `<name>` component itself may contain any number of `/`s —
//! `library/nginx`, `myorg/myteam/myrepo`, ...), so routing dispatches on
//! one `/v2/{*rest}` catch-all and this module does the actual parse. Kept
//! free of any axum/HTTP types so it is trivially unit-testable.

/// A parsed OCI Distribution request, minus the leading `/v2/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciRequest<'a> {
    /// `GET|HEAD /v2/{name}/manifests/{reference}` — `reference` is a tag
    /// or a `sha256:<hex>` digest.
    Manifest { name: &'a str, reference: &'a str },
    /// `GET|HEAD /v2/{name}/blobs/{digest}`.
    Blob { name: &'a str, digest: &'a str },
    /// `GET /v2/{name}/tags/list`.
    TagsList { name: &'a str },
}

const MANIFESTS_SEP: &str = "/manifests/";
const BLOBS_SEP: &str = "/blobs/";
const TAGS_LIST_SUFFIX: &str = "/tags/list";

/// Parses the path remainder after `/v2/` into an [`OciRequest`]. Returns
/// `None` for anything this pull-through proxy does not support — notably
/// blob-upload sub-paths (`/blobs/uploads/...`, push-only) and any path that
/// doesn't match one of the three read endpoints this service implements.
#[must_use]
pub fn parse(rest: &str) -> Option<OciRequest<'_>> {
    if let Some(name) = rest.strip_suffix(TAGS_LIST_SUFFIX) {
        return non_empty(name).map(|name| OciRequest::TagsList { name });
    }
    if let Some(idx) = rest.rfind(MANIFESTS_SEP) {
        let name = &rest[..idx];
        let reference = &rest[idx + MANIFESTS_SEP.len()..];
        return match (non_empty(name), non_empty(reference)) {
            (Some(name), Some(reference)) => Some(OciRequest::Manifest { name, reference }),
            _ => None,
        };
    }
    if let Some(idx) = rest.rfind(BLOBS_SEP) {
        let name = &rest[..idx];
        let digest = &rest[idx + BLOBS_SEP.len()..];
        // "uploads"/"uploads/<uuid>" is the push-only chunked-upload
        // sub-resource — not a digest, and not something this pull-through
        // proxy serves.
        if digest == "uploads" || digest.starts_with("uploads/") {
            return None;
        }
        return match (non_empty(name), non_empty(digest)) {
            (Some(name), Some(digest)) => Some(OciRequest::Blob { name, digest }),
            _ => None,
        };
    }
    None
}

fn non_empty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// Extracts the raw lowercase-hex payload of a `sha256:<hex>` digest string,
/// validating both the algorithm prefix and that the hex payload is exactly
/// 64 lowercase hex characters (a real SHA-256 digest, never
/// case-insensitively "close enough").
#[must_use]
pub fn parse_sha256_digest(digest: &str) -> Option<&str> {
    let hex = digest.strip_prefix("sha256:")?;
    (hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
    .then_some(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parses_manifest_by_tag() {
        assert_eq!(
            parse("library/nginx/manifests/latest"),
            Some(OciRequest::Manifest {
                name: "library/nginx",
                reference: "latest",
            })
        );
    }

    #[test]
    fn parses_manifest_by_digest() {
        let digest = format!("sha256:{HEX}");
        let rest = format!("myorg/myrepo/manifests/{digest}");
        assert_eq!(
            parse(&rest),
            Some(OciRequest::Manifest {
                name: "myorg/myrepo",
                reference: digest.as_str(),
            })
        );
    }

    #[test]
    fn parses_deeply_nested_name() {
        assert_eq!(
            parse("a/b/c/d/manifests/v1.0.0"),
            Some(OciRequest::Manifest {
                name: "a/b/c/d",
                reference: "v1.0.0",
            })
        );
    }

    #[test]
    fn parses_blob_by_digest() {
        let digest = format!("sha256:{HEX}");
        let rest = format!("library/nginx/blobs/{digest}");
        assert_eq!(
            parse(&rest),
            Some(OciRequest::Blob {
                name: "library/nginx",
                digest: digest.as_str(),
            })
        );
    }

    #[test]
    fn parses_tags_list() {
        assert_eq!(
            parse("library/nginx/tags/list"),
            Some(OciRequest::TagsList {
                name: "library/nginx",
            })
        );
    }

    #[test]
    fn rejects_blob_upload_subpaths() {
        assert_eq!(parse("library/nginx/blobs/uploads"), None);
        assert_eq!(parse("library/nginx/blobs/uploads/some-uuid"), None);
    }

    #[test]
    fn rejects_empty_name_or_reference() {
        assert_eq!(parse("/manifests/latest"), None);
        assert_eq!(parse("library/nginx/manifests/"), None);
        assert_eq!(parse("/blobs/sha256:abc"), None);
        assert_eq!(parse("/tags/list"), None);
    }

    #[test]
    fn rejects_unrecognized_shape() {
        assert_eq!(parse("library/nginx"), None);
        assert_eq!(parse(""), None);
        assert_eq!(parse("library/nginx/referrers/sha256:abc"), None);
    }

    #[test]
    fn parse_sha256_digest_accepts_well_formed_sha256() {
        let digest = format!("sha256:{HEX}");
        assert_eq!(parse_sha256_digest(&digest), Some(HEX));
    }

    #[test]
    fn parse_sha256_digest_rejects_tags_and_malformed_digests() {
        assert_eq!(parse_sha256_digest("latest"), None);
        assert_eq!(parse_sha256_digest("sha256:tooshort"), None);
        assert_eq!(parse_sha256_digest("sha512:deadbeef"), None);
        assert_eq!(
            parse_sha256_digest(&format!("sha256:{}", HEX.to_uppercase())),
            None
        );
    }

    #[test]
    fn parse_sha256_digest_extracts_hex_payload() {
        let digest = format!("sha256:{HEX}");
        assert_eq!(parse_sha256_digest(&digest), Some(HEX));
        assert_eq!(parse_sha256_digest("not-a-digest"), None);
    }
}
