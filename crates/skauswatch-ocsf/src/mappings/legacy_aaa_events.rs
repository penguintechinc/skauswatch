//! Legacy `aaa-events-*` → OCSF field mapping. The v1 event documents
//! indexed into `aaa-events-YYYY.MM.DD` had `facility` and `severity` as
//! RFC 5424-style numeric fields, plus a `source` enum (as a string like
//! "auditd", "file", etc.). This module maps those to the same severity
//! scale that `mappings::syslog` uses, ensuring consistency across all
//! normalized sources when the backfill re-indexes them into the unified
//! `skauswatch-logs-*` lake. See `services/svc-ingest/src/main.rs`'s
//! `Command::Backfill` for the backfill job that uses this.

use crate::JsonVal;

/// Maps an RFC 5424-style numeric severity (0-7) to the text bucket
/// `crate::normalize`'s `detect_severity` heuristic understands, matching
/// the syslog mapping exactly: Emergency/Alert/Critical (0-2) → critical;
/// Error (3) → error; Warning (4) → warning; Notice/Informational (5-6) →
/// info; Debug (7+) → debug. This ensures legacy events get the same OCSF
/// `severity_id` they would have received if they had come through the
/// syslog listener.
fn severity_text(severity: i64) -> &'static str {
    match severity {
        0..=2 => "critical",
        3 => "error",
        4 => "warning",
        5 | 6 => "info",
        _ => "debug",
    }
}

/// Normalizes a legacy `aaa-events-*` document into the raw record
/// [`crate::normalize`] expects. A legacy document carries `facility`
/// (numeric, RFC 5424 §6.2.1), `severity` (numeric, RFC 5424 §6.2.1),
/// and `source` (string enum like "auditd", "file", etc.) — all are
/// reshaped into `facility` (numeric), `level` (text, for severity
/// detection), and `source` (string) fields so the normalizer can apply
/// the same detection heuristics.
///
/// # Errors
///
/// Returns `NormalizeError` if the input is not a JSON object.
pub fn legacy_aaa_event_to_ocsf(raw: &JsonVal) -> Result<JsonVal, crate::NormalizeError> {
    // Expect the input to be a JSON object (a deserialized document from
    // the OpenSearch index).
    let mut doc = match raw {
        JsonVal::Obj(fields) => fields.clone(),
        _ => return Err(crate::NormalizeError),
    };

    // Extract severity: look for a numeric "severity" field (RFC 5424 style).
    // Default to 0 (Emergency) if missing or non-numeric.
    let severity = raw
        .get("severity")
        .and_then(|v| match v {
            JsonVal::Num(n) => n.as_i64(),
            _ => None,
        })
        .unwrap_or(0);

    // Update or insert the "level" field (text representation for normalize).
    let level_text = severity_text(severity);
    doc.push(("level".to_owned(), JsonVal::Str(level_text.to_owned())));

    // Facility is preserved as-is if present; not added if missing since it's
    // only evidence (not a detection driver for the normalizer).
    // Source is already a string field (like "auditd", "file", etc.);
    // leave it as-is. The normalizer will use it for class detection.

    Ok(JsonVal::Obj(doc))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn sample_event(severity: i64, facility: i64) -> JsonVal {
        JsonVal::Obj(vec![
            (
                "severity".to_owned(),
                JsonVal::Num(serde_json::Number::from(severity)),
            ),
            (
                "facility".to_owned(),
                JsonVal::Num(serde_json::Number::from(facility)),
            ),
            ("message".to_owned(), JsonVal::Str("Test event".to_owned())),
            ("source".to_owned(), JsonVal::Str("auditd".to_owned())),
            (
                "timestamp".to_owned(),
                JsonVal::Str("2025-01-15T12:30:00Z".to_owned()),
            ),
        ])
    }

    #[test]
    fn legacy_event_facility_severity_integers_map_to_ocsf_severity_id() {
        // Verify that a legacy event with severity=2 (Critical, per RFC 5424)
        // maps to OCSF severity_id=5 (critical) when normalized.
        let raw = sample_event(2, 4);
        let mapped = legacy_aaa_event_to_ocsf(&raw).expect("mapping failed");

        // Check that the level field was set to "critical".
        assert_eq!(
            mapped.get("level").and_then(JsonVal::as_str),
            Some("critical"),
            "severity 2 should map to level=critical"
        );

        // Now normalize and check severity_id.
        let now = chrono::Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        let normalized = crate::normalize(&mapped, "legacy_aaa", now).expect("normalize failed");
        assert_eq!(
            normalized.get("severity_id").and_then(|v| match v {
                JsonVal::Num(n) => n.as_i64(),
                _ => None,
            }),
            Some(5),
            "normalized severity_id should be 5 for critical"
        );
    }

    #[test]
    fn legacy_event_preserves_facility_and_source() {
        let raw = sample_event(3, 4);
        let mapped = legacy_aaa_event_to_ocsf(&raw).expect("mapping failed");

        // Facility should be preserved as-is.
        assert_eq!(
            mapped.get("facility").and_then(|v| match v {
                JsonVal::Num(n) => n.as_i64(),
                _ => None,
            }),
            Some(4),
            "facility should be preserved"
        );

        // Source should be preserved as-is.
        assert_eq!(
            mapped.get("source").and_then(JsonVal::as_str),
            Some("auditd"),
            "source should be preserved"
        );
    }

    #[test]
    fn legacy_event_non_object_input_returns_error() {
        // A non-object (e.g., array, string, number) should return NormalizeError.
        assert!(legacy_aaa_event_to_ocsf(&JsonVal::Str("not an object".to_owned())).is_err());
        assert!(legacy_aaa_event_to_ocsf(&JsonVal::Num(serde_json::Number::from(42))).is_err());
    }

    #[test]
    fn legacy_event_missing_severity_defaults_to_emergency() {
        let raw = JsonVal::Obj(vec![
            ("message".to_owned(), JsonVal::Str("Test".to_owned())),
            ("source".to_owned(), JsonVal::Str("auditd".to_owned())),
        ]);
        let mapped = legacy_aaa_event_to_ocsf(&raw).expect("mapping failed");

        // Missing severity should default to 0 (Emergency) → "critical".
        assert_eq!(
            mapped.get("level").and_then(JsonVal::as_str),
            Some("critical"),
            "missing severity should default to critical"
        );
    }
}
