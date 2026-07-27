//! Content-analysis primitives ported from v1 `scanner/` and `s3/tagger.py`:
//! magic-byte file typing (v1 libmagic → `infer`), MD5/SHA1/SHA256 hashing,
//! and the S3 tag set written after a scan. These operate on the in-memory
//! object bytes (bounded by `MAX_FILE_SIZE_MB`), so no temp files are needed.

// md-5 (digest 0.11) and sha1/sha2 (digest 0.10) expose distinct `Digest`
// traits; sha1 and sha2 share theirs, so one import covers both.
use md5::Digest as _;
use sha1::Digest as _;

/// MIME reported when magic-byte detection yields nothing (v1's libmagic would
/// usually return `text/plain`; `infer` has no text heuristics, so the neutral
/// octet-stream is used).
pub const UNKNOWN_MIME: &str = "application/octet-stream";

/// The three digests v1 recorded for every scanned object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Hashes {
    /// Lowercase hex MD5.
    pub md5: String,
    /// Lowercase hex SHA1.
    pub sha1: String,
    /// Lowercase hex SHA256.
    pub sha256: String,
}

/// Lowercase hex rendering of digest bytes.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Computes MD5/SHA1/SHA256 over `data` (v1 `FileHasher.compute_all`).
pub fn compute_hashes(data: &[u8]) -> Hashes {
    Hashes {
        md5: hex_lower(&md5::Md5::digest(data)),
        sha1: hex_lower(&sha1::Sha1::digest(data)),
        sha256: hex_lower(&sha2::Sha256::digest(data)),
    }
}

/// Detects the MIME type from magic bytes, falling back to [`UNKNOWN_MIME`].
pub fn detect_file_type(data: &[u8]) -> String {
    infer::get(data).map_or_else(|| UNKNOWN_MIME.to_owned(), |t| t.mime_type().to_owned())
}

/// v1 threat label: `malware`, `pup`, or `clean`.
pub fn threat_label(is_malware: bool, is_pup: bool) -> &'static str {
    if is_malware {
        "malware"
    } else if is_pup {
        "pup"
    } else {
        "clean"
    }
}

/// The S3 tag set v1 `S3Tagger.apply_scan_tags` wrote (`malware`, `pup`,
/// `threat`, `scanTime` ms, `fileType`).
pub fn scan_tags(
    is_malware: bool,
    is_pup: bool,
    file_type: &str,
    scan_time_ms: i64,
) -> Vec<(String, String)> {
    let b = |v: bool| if v { "true" } else { "false" }.to_owned();
    vec![
        ("malware".to_owned(), b(is_malware)),
        ("pup".to_owned(), b(is_pup)),
        (
            "threat".to_owned(),
            threat_label(is_malware, is_pup).to_owned(),
        ),
        ("scanTime".to_owned(), scan_time_ms.to_string()),
        ("fileType".to_owned(), file_type.to_owned()),
    ]
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn hashes_match_known_vectors() {
        // "abc" reference digests.
        let h = compute_hashes(b"abc");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            h.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn empty_input_hashes() {
        let h = compute_hashes(b"");
        assert_eq!(h.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn detects_png_magic_and_falls_back() {
        let png = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0];
        assert_eq!(detect_file_type(&png), "image/png");
        assert_eq!(detect_file_type(b"plain text"), UNKNOWN_MIME);
    }

    #[test]
    fn threat_label_precedence() {
        assert_eq!(threat_label(true, true), "malware");
        assert_eq!(threat_label(false, true), "pup");
        assert_eq!(threat_label(false, false), "clean");
    }

    #[test]
    fn tags_shape() {
        let tags = scan_tags(false, false, "application/pdf", 1234);
        assert_eq!(tags.len(), 5);
        assert_eq!(tags[0], ("malware".to_owned(), "false".to_owned()));
        assert_eq!(tags[2], ("threat".to_owned(), "clean".to_owned()));
        assert_eq!(tags[3], ("scanTime".to_owned(), "1234".to_owned()));
    }
}
