//! OCSF schema constants — a byte-for-byte port of v1 `ocsf/schema.py`: the
//! `class_uid` → class name table and the metadata schema version stamped on
//! every normalized event. Task 1.3 adds schema validation for native OCSF
//! documents (strict required-field validation), separate from generic JSON
//! normalization (permissive).

use crate::JsonVal;

/// OCSF metadata schema version stamped on every event (v1 `"1.3.0"`).
pub const OCSF_VERSION: &str = "1.3.0";

/// Required OCSF fields — a document with all of these is treated as native
/// OCSF and undergoes strict schema validation; missing any required field
/// causes a 400 rejection.
const REQUIRED_FIELDS: &[&str] = &[
    "class_uid",
    "class_name",
    "time",
    "severity_id",
    "status_id",
    "message",
    "metadata",
    "raw_data",
];

/// Maps `class_uid` to the OCSF class name (v1 `OCSF_CLASSES`, default
/// `"unknown"`).
pub fn class_name(class_uid: i64) -> &'static str {
    match class_uid {
        2001 => "security_finding",
        3002 => "authentication",
        4001 => "network_activity",
        4003 => "file_activity",
        6003 => "api_activity",
        _ => "unknown",
    }
}

/// Classifies a document as native OCSF if it has OCSF markers (class_uid or
/// metadata field present). Native OCSF documents are strictly validated for
/// required fields; generic JSON is normalized (permissive).
pub fn is_native_ocsf(record: &JsonVal) -> bool {
    record.get("class_uid").is_some() || record.get("metadata").is_some()
}

/// Validates a native OCSF document for all required fields. Returns an error
/// string describing the first missing field, or `None` if valid.
pub fn validate_required_fields(record: &JsonVal) -> Result<(), &'static str> {
    for field in REQUIRED_FIELDS {
        if record.get(field).is_none() {
            return Err("missing required OCSF field");
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn class_name_defaults_to_unknown_for_unmapped_uid() {
        assert_eq!(class_name(9999), "unknown");
    }
}
