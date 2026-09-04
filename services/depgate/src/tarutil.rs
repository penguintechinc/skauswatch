//! Minimal, dependency-free tar reader (plus a `#[cfg(test)]`-only writer)
//! used by `crate::heuristics::evaluate_pypi` to check PyPI sdist archives
//! for a `setup.py` entry without pulling in the `tar` crate for a single
//! presence/content check. Deliberately narrow: handles plain
//! ustar/pre-POSIX regular-file entries only (no GNU long-name/PAX
//! extended-header interpretation) — sufficient for the near-universal
//! `<name>-<version>/setup.py` layout, well under the tar header's
//! 100-byte name field.

use std::io::Read;

use flate2::read::GzDecoder;

const BLOCK: usize = 512;

/// Ungzips `data` and returns the bytes of the first tar entry whose name
/// ends with `suffix` (e.g. `"setup.py"`). `None` if gunzip fails, the
/// archive is malformed/truncated, or no matching entry exists — every
/// failure mode collapses to "nothing found" since the caller
/// (`crate::heuristics::evaluate_pypi`) treats this as a plain absence
/// check, not a hard error.
#[must_use]
pub fn find_gzip_tar_entry_ending_with(data: &[u8], suffix: &str) -> Option<Vec<u8>> {
    let mut tar = Vec::new();
    GzDecoder::new(data).read_to_end(&mut tar).ok()?;
    find_tar_entry_ending_with(&tar, suffix)
}

fn find_tar_entry_ending_with(tar: &[u8], suffix: &str) -> Option<Vec<u8>> {
    let mut offset = 0usize;
    while offset + BLOCK <= tar.len() {
        let header = &tar[offset..offset + BLOCK];
        if header.iter().all(|&b| b == 0) {
            break; // end-of-archive marker (two all-zero blocks)
        }
        let name = ascii_field(&header[0..100]);
        let size = octal_field(&header[124..136])?;
        let typeflag = header[156];
        let data_start = offset + BLOCK;
        let data_end = data_start.checked_add(size)?;
        if data_end > tar.len() {
            break; // truncated/malformed archive
        }
        if (typeflag == b'0' || typeflag == 0) && name.ends_with(suffix) {
            return Some(tar[data_start..data_end].to_vec());
        }
        let padded = size.div_ceil(BLOCK) * BLOCK;
        offset = data_start.checked_add(padded)?;
    }
    None
}

fn ascii_field(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn octal_field(field: &[u8]) -> Option<usize> {
    let s = ascii_field(field);
    let s = s.trim_matches(|c: char| c == ' ' || c == '\0');
    if s.is_empty() {
        return Some(0);
    }
    usize::from_str_radix(s, 8).ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
pub(crate) mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    fn write_octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        let s = format!("{value:0width$o}");
        let start = s.len().saturating_sub(width);
        let s = &s[start..];
        field[..s.len()].copy_from_slice(s.as_bytes());
        field[s.len()] = 0;
    }

    fn tar_header(name: &str, size: usize) -> [u8; BLOCK] {
        let mut header = [0u8; BLOCK];
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(100);
        header[0..name_len].copy_from_slice(&name_bytes[..name_len]);
        write_octal(&mut header[100..108], 0o644); // mode
        write_octal(&mut header[108..116], 0); // uid
        write_octal(&mut header[116..124], 0); // gid
        write_octal(&mut header[124..136], size as u64); // size
        write_octal(&mut header[136..148], 0); // mtime
        header[156] = b'0'; // typeflag: regular file
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        // Checksum: sum of all header bytes with the checksum field itself
        // treated as 8 ASCII spaces, per the POSIX tar spec.
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        let chksum = format!("{sum:06o}\0 ");
        header[148..148 + chksum.len()].copy_from_slice(chksum.as_bytes());
        header
    }

    /// Builds a minimal, valid gzip'd tar archive containing exactly the
    /// given `(name, contents)` entries — a test-only fixture builder so
    /// `crate::heuristics`'s PyPI sdist tests don't need a real tarball
    /// checked into the repo.
    pub(crate) fn build_gzip_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, contents) in entries {
            tar.extend_from_slice(&tar_header(name, contents.len()));
            tar.extend_from_slice(contents);
            let pad = contents.len().div_ceil(BLOCK) * BLOCK - contents.len();
            tar.extend(std::iter::repeat_n(0u8, pad));
        }
        tar.extend_from_slice(&[0u8; BLOCK * 2]); // end-of-archive marker
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar)
            .expect("gzip encode into an in-memory Vec cannot fail");
        gz.finish()
            .expect("gzip finish into an in-memory Vec cannot fail")
    }

    #[test]
    fn round_trips_a_single_entry() {
        let archive = build_gzip_tar(&[("pkg-1.0.0/setup.py", b"print('hi')")]);
        let found = find_gzip_tar_entry_ending_with(&archive, "setup.py").expect("found");
        assert_eq!(found, b"print('hi')");
    }

    #[test]
    fn returns_none_when_no_entry_matches() {
        let archive = build_gzip_tar(&[("pkg-1.0.0/README.md", b"hello")]);
        assert_eq!(find_gzip_tar_entry_ending_with(&archive, "setup.py"), None);
    }

    #[test]
    fn returns_none_for_non_gzip_bytes() {
        assert_eq!(
            find_gzip_tar_entry_ending_with(b"not gzip data", "setup.py"),
            None
        );
    }

    #[test]
    fn finds_the_matching_entry_among_several() {
        let archive = build_gzip_tar(&[
            ("pkg-1.0.0/README.md", b"hello"),
            ("pkg-1.0.0/setup.py", b"from setuptools import setup"),
            ("pkg-1.0.0/pkg/__init__.py", b""),
        ]);
        let found = find_gzip_tar_entry_ending_with(&archive, "setup.py").expect("found");
        assert_eq!(found, b"from setuptools import setup");
    }

    #[test]
    fn empty_archive_finds_nothing() {
        let archive = build_gzip_tar(&[]);
        assert_eq!(find_gzip_tar_entry_ending_with(&archive, "setup.py"), None);
    }
}
