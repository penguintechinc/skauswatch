//! Syslog (RFC 3164/5424) → OCSF field mapping (`docs/v2-port/ingest-module-spec.md`
//! §4a). [`ParsedSyslog`] is the normalized tuple both RFC parsers in
//! `services/svc-ingest/src/listeners/syslog/parser.rs` produce —
//! `(severity, facility, hostname, message, timestamp)` per the Spec, plus
//! RFC 5424's optional APP-NAME/PROCID/MSGID (always `None` for RFC 3164,
//! which has no equivalent fields). [`to_ocsf_fields`] shapes that struct
//! into the raw record [`crate::normalize`] expects, the same
//! "source-specific mapping ahead of the shared normalizer" role
//! `mappings::otlp`/`mappings::generic` will fill for their own sources.

use chrono::{DateTime, Utc};

use crate::JsonVal;

/// One syslog message, normalized from either RFC 3164 or RFC 5424 into a
/// single shape (Spec §4a: "Both emit a normalized tuple: `(severity,
/// facility, hostname, message, timestamp)`"). `app_name`/`proc_id`/
/// `msg_id` are RFC 5424-only fields (`None` for anything parsed as RFC
/// 3164, which carries no equivalent structured fields).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSyslog {
    /// Numeric severity (`PRI % 8`), RFC 5424 severity levels (0 =
    /// Emergency .. 7 = Debug) — RFC 3164 uses the same numeric scale.
    pub severity: u8,
    /// Numeric facility (`PRI / 8`).
    pub facility: u8,
    /// Sending host, as reported in the message itself (Spec §4a: "used as
    /// `src_hostname` or `host`" — the original network-level source is
    /// lost if the message came via a forwarder, a documented P1
    /// limitation).
    pub hostname: String,
    /// The message body after the header (RFC 3164) or after
    /// STRUCTURED-DATA (RFC 5424).
    pub message: String,
    /// The message's timestamp — best-effort "assume this year" for RFC
    /// 3164 (which carries no year at all), full-fidelity for RFC 5424's
    /// ISO 8601 timestamp.
    pub timestamp: DateTime<Utc>,
    /// RFC 5424 APP-NAME, when present and not the `-` NILVALUE sentinel.
    pub app_name: Option<String>,
    /// RFC 5424 PROCID, when present and not the `-` NILVALUE sentinel.
    pub proc_id: Option<String>,
    /// RFC 5424 MSGID, when present and not the `-` NILVALUE sentinel.
    pub msg_id: Option<String>,
}

/// Maps a syslog numeric severity (RFC 5424 §6.2.1's 0-7 scale, which RFC
/// 3164 also uses) to the text bucket [`crate::normalize`]'s
/// `detect_severity` heuristic already understands, so a syslog event gets
/// the same OCSF `severity_id` a hand-written `{"level": "..."}` record
/// would. Documented mapping choice (no single canonical syslog-severity →
/// OCSF-severity table exists): Emergency/Alert/Critical (0-2) → critical;
/// Error (3) → error; Warning (4) → warning; Notice/Informational (5-6) →
/// info; Debug (7, and any out-of-range value) → debug.
fn severity_text(severity: u8) -> &'static str {
    match severity {
        0..=2 => "critical",
        3 => "error",
        4 => "warning",
        5 | 6 => "info",
        _ => "debug",
    }
}

/// Shapes a [`ParsedSyslog`] into the raw record [`crate::normalize`]
/// expects: `message`/`level`/`timestamp` drive its detection heuristics
/// directly, `host`/`facility`/`syslog_severity` (and the RFC
/// 5424-specific `app_name`/`proc_id`/`msg_id`, when present) are carried
/// through into `raw_data` as evidence.
#[must_use]
pub fn to_ocsf_fields(parsed: &ParsedSyslog) -> JsonVal {
    let mut fields = vec![
        ("message".to_owned(), JsonVal::Str(parsed.message.clone())),
        (
            "level".to_owned(),
            JsonVal::Str(severity_text(parsed.severity).to_owned()),
        ),
        (
            "timestamp".to_owned(),
            JsonVal::Str(parsed.timestamp.to_rfc3339()),
        ),
        ("host".to_owned(), JsonVal::Str(parsed.hostname.clone())),
        (
            "facility".to_owned(),
            JsonVal::Num(serde_json::Number::from(parsed.facility)),
        ),
        (
            "syslog_severity".to_owned(),
            JsonVal::Num(serde_json::Number::from(parsed.severity)),
        ),
    ];
    if let Some(app_name) = &parsed.app_name {
        fields.push(("app_name".to_owned(), JsonVal::Str(app_name.clone())));
    }
    if let Some(proc_id) = &parsed.proc_id {
        fields.push(("proc_id".to_owned(), JsonVal::Str(proc_id.clone())));
    }
    if let Some(msg_id) = &parsed.msg_id {
        fields.push(("msg_id".to_owned(), JsonVal::Str(msg_id.clone())));
    }
    JsonVal::Obj(fields)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn sample(severity: u8) -> ParsedSyslog {
        ParsedSyslog {
            severity,
            facility: 4,
            hostname: "host1".to_owned(),
            message: "sshd: Failed password for root".to_owned(),
            timestamp: Utc.with_ymd_and_hms(2025, 1, 15, 12, 30, 0).unwrap(),
            app_name: None,
            proc_id: None,
            msg_id: None,
        }
    }

    #[test]
    fn to_ocsf_fields_carries_message_level_timestamp_and_host() {
        let doc = to_ocsf_fields(&sample(2));
        assert_eq!(
            doc.get("message").and_then(JsonVal::as_str),
            Some("sshd: Failed password for root")
        );
        assert_eq!(doc.get("level").and_then(JsonVal::as_str), Some("critical"));
        assert_eq!(
            doc.get("timestamp").and_then(JsonVal::as_str),
            Some("2025-01-15T12:30:00+00:00")
        );
        assert_eq!(doc.get("host").and_then(JsonVal::as_str), Some("host1"));
    }

    #[test]
    fn to_ocsf_fields_feeds_normalize_severity_heuristic() {
        // End-to-end: `to_ocsf_fields`'s "level" text must actually drive
        // `crate::normalize`'s OCSF severity_id, not just be present.
        let now = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        let doc = crate::normalize(&to_ocsf_fields(&sample(2)), "syslog", now).unwrap();
        assert_eq!(
            doc.get("severity_id").and_then(|v| match v {
                JsonVal::Num(n) => n.as_i64(),
                _ => None,
            }),
            Some(5),
            "severity 2 (Critical) must map through to OCSF severity_id 5"
        );
    }

    #[test]
    fn severity_text_covers_the_full_rfc5424_scale() {
        assert_eq!(severity_text(0), "critical");
        assert_eq!(severity_text(1), "critical");
        assert_eq!(severity_text(2), "critical");
        assert_eq!(severity_text(3), "error");
        assert_eq!(severity_text(4), "warning");
        assert_eq!(severity_text(5), "info");
        assert_eq!(severity_text(6), "info");
        assert_eq!(severity_text(7), "debug");
    }

    #[test]
    fn to_ocsf_fields_includes_rfc5424_optional_fields_when_present() {
        let mut parsed = sample(6);
        parsed.app_name = Some("sshd".to_owned());
        parsed.proc_id = Some("1234".to_owned());
        parsed.msg_id = Some("ID47".to_owned());
        let doc = to_ocsf_fields(&parsed);
        assert_eq!(doc.get("app_name").and_then(JsonVal::as_str), Some("sshd"));
        assert_eq!(doc.get("proc_id").and_then(JsonVal::as_str), Some("1234"));
        assert_eq!(doc.get("msg_id").and_then(JsonVal::as_str), Some("ID47"));
    }

    #[test]
    fn to_ocsf_fields_omits_rfc5424_optional_fields_when_absent() {
        let doc = to_ocsf_fields(&sample(6));
        assert!(doc.get("app_name").is_none());
        assert!(doc.get("proc_id").is_none());
        assert!(doc.get("msg_id").is_none());
    }
}
