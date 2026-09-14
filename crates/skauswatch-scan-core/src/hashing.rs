//! Content-identification primitives extracted from `s3scan/src/scan.rs`
//! (itself ported from v1 `scanner/` and `s3/tagger.py`): magic-byte file
//! typing (v1 libmagic → `infer`) and MD5/SHA1/SHA256 hashing. These operate
//! on in-memory bytes only — no temp files, no S3 awareness.

// md-5 (digest 0.11) and sha1/sha2 (digest 0.10) expose distinct `Digest`
// traits; sha1 and sha2 share theirs, so one import covers both.
use md5::Digest as _;
use sha1::Digest as _;

/// MIME reported when magic-byte detection yields nothing (v1's libmagic
/// would usually return `text/plain`; `infer` has no text heuristics, so the
/// neutral octet-stream is used).
pub const UNKNOWN_MIME: &str = "application/octet-stream";

/// The three digests every scan-core consumer records for a scanned object.
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
#[must_use]
pub fn compute_hashes(data: &[u8]) -> Hashes {
    Hashes {
        md5: hex_lower(&md5::Md5::digest(data)),
        sha1: hex_lower(&sha1::Sha1::digest(data)),
        sha256: hex_lower(&sha2::Sha256::digest(data)),
    }
}

/// Detects the MIME type from magic bytes, falling back to [`UNKNOWN_MIME`].
#[must_use]
pub fn detect_file_type(data: &[u8]) -> String {
    infer::get(data).map_or_else(|| UNKNOWN_MIME.to_owned(), |t| t.mime_type().to_owned())
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
}
