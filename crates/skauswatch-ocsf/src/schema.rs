//! OCSF schema constants — a byte-for-byte port of v1 `ocsf/schema.py`: the
//! `class_uid` → class name table and the metadata schema version stamped on
//! every normalized event.

/// OCSF metadata schema version stamped on every event (v1 `"1.3.0"`).
pub const OCSF_VERSION: &str = "1.3.0";

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn class_name_defaults_to_unknown_for_unmapped_uid() {
        assert_eq!(class_name(9999), "unknown");
    }
}
