//! Bucket enumeration filtering and per-object re-dispatch. A job-level task
//! (empty object key) enumerates the configured bucket; each surviving object
//! is re-published to `s3scan:tasks` in the manager's `scan_task_fields` shape
//! so a per-object task is indistinguishable from a manager-published one.
//!
//! v1 `s3scan` never enumerated (the never-registered gRPC `ScanJobManager`
//! did); the v2 manager moved enumeration into the worker (empty `object_key`
//! ⇒ "worker enumerates"). The filter rules mirror the bucket-config surface:
//! `prefix_filter` (applied as the S3 list prefix), `file_types_filter`
//! (extension allow-list), and `max_file_size_mb` (size skip).

use skauswatch_streams::{EntryFields, py_bool, py_now_isoformat};

/// Per-object enumeration decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Dispatch a scan for this object.
    Scan,
    /// Skip: object exceeds the configured max size.
    SkipTooLarge,
    /// Skip: folder marker or extension not in the allow-list.
    SkipFiltered,
}

/// Classifies one listed object against the bucket filters.
///
/// - Keys ending in `/` (folder placeholders) are filtered.
/// - When `file_types` is non-empty, only keys whose (lowercased) name ends
///   with one of the dot-prefixed extensions survive.
/// - Objects larger than `max_bytes` are skipped as too large.
pub fn classify_object(key: &str, size: i64, file_types: &[String], max_bytes: u64) -> Decision {
    if key.ends_with('/') {
        return Decision::SkipFiltered;
    }
    if !file_types.is_empty() {
        let lower = key.to_lowercase();
        let matched = file_types
            .iter()
            .any(|ft| lower.ends_with(&ft.to_lowercase()));
        if !matched {
            return Decision::SkipFiltered;
        }
    }
    if size < 0 || size as u64 > max_bytes {
        return Decision::SkipTooLarge;
    }
    Decision::Scan
}

/// Builds the per-object re-dispatch fields, byte-identical to the manager's
/// `scan_task_fields` (`scan_enabled` always `True` on the scan path; the
/// `submitted_at` stamp is refreshed to now).
pub fn dispatch_fields(
    job_id: &str,
    bucket_config_id: i32,
    object_key: &str,
    object_size: i64,
    object_etag: &str,
    yara_enabled: bool,
) -> EntryFields {
    vec![
        ("job_id".to_owned(), job_id.to_owned()),
        ("bucket_config_id".to_owned(), bucket_config_id.to_string()),
        ("object_key".to_owned(), object_key.to_owned()),
        ("object_size".to_owned(), object_size.to_string()),
        ("object_etag".to_owned(), object_etag.to_owned()),
        ("scan_enabled".to_owned(), py_bool(true).to_owned()),
        ("yara_enabled".to_owned(), py_bool(yara_enabled).to_owned()),
        ("submitted_at".to_owned(), py_now_isoformat()),
    ]
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    const MB: u64 = 1024 * 1024;

    #[test]
    fn scans_matching_object() {
        assert_eq!(
            classify_object("uploads/a.bin", 10, &[], 100 * MB),
            Decision::Scan
        );
    }

    #[test]
    fn skips_folder_marker() {
        assert_eq!(
            classify_object("uploads/", 0, &[], 100 * MB),
            Decision::SkipFiltered
        );
    }

    #[test]
    fn skips_too_large() {
        assert_eq!(
            classify_object("a.bin", (101 * MB) as i64, &[], 100 * MB),
            Decision::SkipTooLarge
        );
    }

    #[test]
    fn extension_allow_list_filters() {
        let types = vec![".exe".to_owned(), ".dll".to_owned()];
        assert_eq!(
            classify_object("a/evil.EXE", 5, &types, 100 * MB),
            Decision::Scan
        );
        assert_eq!(
            classify_object("a/report.pdf", 5, &types, 100 * MB),
            Decision::SkipFiltered
        );
    }

    #[test]
    fn dispatch_fields_match_manager_shape() {
        let f = dispatch_fields("job-1", 7, "uploads/a.bin", 1024, "\"etag\"", true);
        let keys: Vec<&str> = f.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "job_id",
                "bucket_config_id",
                "object_key",
                "object_size",
                "object_etag",
                "scan_enabled",
                "yara_enabled",
                "submitted_at",
            ]
        );
        // Spot-check the redis-py encodings.
        assert_eq!(f[1].1, "7");
        assert_eq!(f[3].1, "1024");
        assert_eq!(f[5].1, "True");
        assert_eq!(f[6].1, "True");
    }
}
