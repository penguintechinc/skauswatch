//! Parsing of `s3scan:tasks` entries into the task variants the manager
//! publishes. Three producer shapes land on this stream (see
//! `services/manager/src/routes/s3_scan.rs` and
//! `src/grpc/s3_scan_service.rs`):
//!
//! - `scan_task_fields` — `{job_id, bucket_config_id, object_key, object_size,
//!   object_etag, scan_enabled, yara_enabled, submitted_at}`. Empty
//!   `object_key` ⇒ enumerate the bucket; a filled key ⇒ scan that object; an
//!   empty `bucket_config_id` ⇒ an ad-hoc upload (`job_id` = scan id,
//!   `object_key` = `{scan_id}/{filename}`).
//! - `submit_task_fields` — the gRPC `SubmitScanTask` shape carrying inline S3
//!   credentials (`endpoint_url`/`access_key`/`secret_key`/…).
//!
//! All values arrive as redis-py strings: booleans are `"True"`/`"False"`,
//! absent optionals are `""`.

use skauswatch_streams::StreamEntry;

/// A parsed unit of work from `s3scan:tasks`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Task {
    /// Job-level dispatch with an empty object key: enumerate the bucket and
    /// re-dispatch one per-object task per matching object.
    Enumerate(EnumerateTask),
    /// Scan one object addressed by a stored bucket config.
    BucketObject(BucketObjectTask),
    /// Scan one object using credentials carried inline (gRPC full task).
    InlineObject(InlineObjectTask),
    /// Scan one ad-hoc upload (no bucket config; content lives in the ad-hoc
    /// bucket keyed `{scan_id}/{filename}`).
    Adhoc(AdhocTask),
}

/// Job-level bucket enumeration request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumerateTask {
    /// Scan-job UUID (the `s3_scan_jobs.job_id` column).
    pub job_id: String,
    /// Bucket config id to resolve credentials + filters from.
    pub bucket_config_id: i32,
    /// Whether YARA is requested for the objects (carried through re-dispatch).
    pub yara_enabled: bool,
}

/// Per-object scan against a stored bucket config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketObjectTask {
    /// Scan-job UUID.
    pub job_id: String,
    /// Bucket config id (credentials + endpoint).
    pub bucket_config_id: i32,
    /// S3 object key to scan.
    pub object_key: String,
    /// Object size in bytes as advertised at enumeration time (0 if unknown).
    pub object_size: i64,
    /// Object ETag from enumeration (empty if unknown).
    pub object_etag: String,
    /// Whether YARA is requested.
    pub yara_enabled: bool,
}

/// Per-object scan with inline credentials (gRPC `SubmitScanTask`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineObjectTask {
    /// Task id from the gRPC request.
    pub task_id: String,
    /// Scan-job UUID.
    pub job_id: String,
    /// Bucket config id when known (0/absent ⇒ `None`).
    pub bucket_config_id: Option<i32>,
    /// S3 object key.
    pub object_key: String,
    /// Object size in bytes (0 if unknown).
    pub object_size: i64,
    /// S3 endpoint URL.
    pub endpoint_url: String,
    /// Bucket name.
    pub bucket_name: String,
    /// Access key id.
    pub access_key: String,
    /// Secret access key.
    pub secret_key: String,
    /// Region.
    pub region: String,
    /// Use TLS.
    pub use_ssl: bool,
    /// Path-style addressing.
    pub path_style: bool,
    /// Whether YARA is requested.
    pub yara_enabled: bool,
}

/// Ad-hoc upload scan request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdhocTask {
    /// Ad-hoc scan id (the `adhoc_scan_results.scan_id` column).
    pub scan_id: String,
    /// Object key within the ad-hoc bucket: `{scan_id}/{filename}`.
    pub object_key: String,
    /// Object size in bytes (0 if unknown).
    pub object_size: i64,
    /// Whether YARA is requested.
    pub yara_enabled: bool,
}

/// Reasons an entry cannot be turned into a [`Task`]. These are permanent
/// (malformed) failures — the handler acks rather than retries them.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    /// A required field was missing or empty.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// A numeric field could not be parsed.
    #[error("invalid integer for field {field}: {value:?}")]
    InvalidInt {
        /// Field name.
        field: &'static str,
        /// Offending raw value.
        value: String,
    },
}

/// Field value or `""` when absent.
fn field<'a>(e: &'a StreamEntry, key: &str) -> &'a str {
    e.get(key).unwrap_or("")
}

/// Python `str(bool)` decode — `"True"` (case-insensitive) is true, all else
/// false, matching the producer's `py_bool`.
fn parse_py_bool(s: &str) -> bool {
    s.eq_ignore_ascii_case("true")
}

/// Parses a required non-empty field.
fn required<'a>(e: &'a StreamEntry, key: &'static str) -> Result<&'a str, ParseError> {
    let v = field(e, key);
    if v.is_empty() {
        Err(ParseError::MissingField(key))
    } else {
        Ok(v)
    }
}

/// Parses an integer field, defaulting to 0 when empty.
fn parse_int_or_zero(e: &StreamEntry, key: &'static str) -> Result<i64, ParseError> {
    let v = field(e, key);
    if v.is_empty() {
        return Ok(0);
    }
    v.parse::<i64>().map_err(|_| ParseError::InvalidInt {
        field: key,
        value: v.to_owned(),
    })
}

/// Parses a required i32 field.
fn parse_i32(e: &StreamEntry, key: &'static str) -> Result<i32, ParseError> {
    let v = required(e, key)?;
    v.parse::<i32>().map_err(|_| ParseError::InvalidInt {
        field: key,
        value: v.to_owned(),
    })
}

impl Task {
    /// Classifies and parses one `s3scan:tasks` entry.
    ///
    /// # Errors
    /// Returns [`ParseError`] for malformed entries (missing `job_id`,
    /// unparseable ids); callers should ack such poison entries.
    pub fn parse(e: &StreamEntry) -> Result<Task, ParseError> {
        let job_id = required(e, "job_id")?.to_owned();
        let yara_enabled = parse_py_bool(field(e, "yara_enabled"));

        // gRPC full-task: inline credentials present.
        if !field(e, "endpoint_url").is_empty() && !field(e, "access_key").is_empty() {
            let bucket_config_id = match field(e, "bucket_config_id") {
                "" => None,
                other => other.parse::<i32>().ok().filter(|v| *v != 0),
            };
            return Ok(Task::InlineObject(InlineObjectTask {
                task_id: field(e, "task_id").to_owned(),
                job_id,
                bucket_config_id,
                object_key: required(e, "object_key")?.to_owned(),
                object_size: parse_int_or_zero(e, "object_size")?,
                endpoint_url: field(e, "endpoint_url").to_owned(),
                bucket_name: required(e, "bucket_name")?.to_owned(),
                access_key: field(e, "access_key").to_owned(),
                secret_key: field(e, "secret_key").to_owned(),
                region: {
                    let r = field(e, "region");
                    if r.is_empty() {
                        "us-east-1".to_owned()
                    } else {
                        r.to_owned()
                    }
                },
                use_ssl: parse_py_bool_default(field(e, "use_ssl"), true),
                path_style: parse_py_bool(field(e, "path_style")),
                yara_enabled,
            }));
        }

        // Ad-hoc upload: no bucket config id.
        if field(e, "bucket_config_id").is_empty() {
            return Ok(Task::Adhoc(AdhocTask {
                scan_id: job_id,
                object_key: required(e, "object_key")?.to_owned(),
                object_size: parse_int_or_zero(e, "object_size")?,
                yara_enabled,
            }));
        }

        // Bucket-config-backed: enumerate (empty key) or per-object.
        let bucket_config_id = parse_i32(e, "bucket_config_id")?;
        if field(e, "object_key").is_empty() {
            Ok(Task::Enumerate(EnumerateTask {
                job_id,
                bucket_config_id,
                yara_enabled,
            }))
        } else {
            Ok(Task::BucketObject(BucketObjectTask {
                job_id,
                bucket_config_id,
                object_key: field(e, "object_key").to_owned(),
                object_size: parse_int_or_zero(e, "object_size")?,
                object_etag: field(e, "object_etag").to_owned(),
                yara_enabled,
            }))
        }
    }
}

/// `parse_py_bool` with an explicit default for empty input (v1 `use_ssl`
/// default true).
fn parse_py_bool_default(s: &str, default: bool) -> bool {
    if s.is_empty() {
        default
    } else {
        parse_py_bool(s)
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn entry(fields: &[(&str, &str)]) -> StreamEntry {
        StreamEntry {
            id: "1-0".to_owned(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<HashMap<_, _>>(),
        }
    }

    // Exact field shape emitted by manager routes/s3_scan.rs `scan_task_fields`
    // for a REST trigger-scan (job-level enumerate).
    #[test]
    fn parses_job_level_enumerate() {
        let e = entry(&[
            ("job_id", "job-uuid"),
            ("bucket_config_id", "7"),
            ("object_key", ""),
            ("object_size", "0"),
            ("object_etag", ""),
            ("scan_enabled", "True"),
            ("yara_enabled", "False"),
            ("submitted_at", "2026-07-22T09:30:00"),
        ]);
        assert_eq!(
            Task::parse(&e),
            Ok(Task::Enumerate(EnumerateTask {
                job_id: "job-uuid".to_owned(),
                bucket_config_id: 7,
                yara_enabled: false,
            }))
        );
    }

    #[test]
    fn parses_per_object_redispatch() {
        let e = entry(&[
            ("job_id", "job-uuid"),
            ("bucket_config_id", "7"),
            ("object_key", "uploads/a.bin"),
            ("object_size", "1024"),
            ("object_etag", "\"abc\""),
            ("scan_enabled", "True"),
            ("yara_enabled", "True"),
            ("submitted_at", "2026-07-22T09:30:00"),
        ]);
        assert_eq!(
            Task::parse(&e),
            Ok(Task::BucketObject(BucketObjectTask {
                job_id: "job-uuid".to_owned(),
                bucket_config_id: 7,
                object_key: "uploads/a.bin".to_owned(),
                object_size: 1024,
                object_etag: "\"abc\"".to_owned(),
                yara_enabled: true,
            }))
        );
    }

    // Manager grpc/s3_scan_service.rs `adhoc_task_fields` shape.
    #[test]
    fn parses_adhoc() {
        let e = entry(&[
            ("job_id", "scan-uuid"),
            ("bucket_config_id", ""),
            ("object_key", "scan-uuid/a.bin"),
            ("object_size", "7"),
            ("object_etag", ""),
            ("scan_enabled", "True"),
            ("yara_enabled", "True"),
            ("submitted_at", "2026-07-22T09:30:00"),
        ]);
        assert_eq!(
            Task::parse(&e),
            Ok(Task::Adhoc(AdhocTask {
                scan_id: "scan-uuid".to_owned(),
                object_key: "scan-uuid/a.bin".to_owned(),
                object_size: 7,
                yara_enabled: true,
            }))
        );
    }

    // Manager grpc/s3_scan_service.rs `submit_task_fields` shape.
    #[test]
    fn parses_inline_grpc_full_task() {
        let e = entry(&[
            ("task_id", "task-1"),
            ("job_id", "job-1"),
            ("bucket_config_id", "3"),
            ("object_key", "path/file.bin"),
            ("object_size", "42"),
            ("endpoint_url", "https://s3.example"),
            ("bucket_name", "bkt"),
            ("access_key", "AK"),
            ("secret_key", "SK"),
            ("region", "us-east-1"),
            ("use_ssl", "True"),
            ("path_style", "False"),
            ("yara_enabled", "True"),
            ("submitted_at", "2026-07-22T09:30:00"),
        ]);
        assert_eq!(
            Task::parse(&e),
            Ok(Task::InlineObject(InlineObjectTask {
                task_id: "task-1".to_owned(),
                job_id: "job-1".to_owned(),
                bucket_config_id: Some(3),
                object_key: "path/file.bin".to_owned(),
                object_size: 42,
                endpoint_url: "https://s3.example".to_owned(),
                bucket_name: "bkt".to_owned(),
                access_key: "AK".to_owned(),
                secret_key: "SK".to_owned(),
                region: "us-east-1".to_owned(),
                use_ssl: true,
                path_style: false,
                yara_enabled: true,
            }))
        );
    }

    #[test]
    fn missing_job_id_is_parse_error() {
        let e = entry(&[("bucket_config_id", "7"), ("object_key", "")]);
        assert_eq!(Task::parse(&e), Err(ParseError::MissingField("job_id")));
    }

    #[test]
    fn non_numeric_bucket_config_is_parse_error() {
        let e = entry(&[
            ("job_id", "j"),
            ("bucket_config_id", "notanint"),
            ("object_key", ""),
        ]);
        assert!(matches!(
            Task::parse(&e),
            Err(ParseError::InvalidInt {
                field: "bucket_config_id",
                ..
            })
        ));
    }

    #[test]
    fn py_bool_decodes_capitalized() {
        assert!(parse_py_bool("True"));
        assert!(!parse_py_bool("False"));
        assert!(!parse_py_bool(""));
        assert!(parse_py_bool_default("", true));
        assert!(!parse_py_bool_default("False", true));
    }
}
