//! OCSF normalization — a byte-for-byte port of v1 `ocsf/normalizer.py` +
//! `ocsf/schema.py`. Maps an arbitrary log record to the OCSF event document
//! the v1 service indexed into OpenSearch, preserving field names, key order,
//! class/severity/status detection, and `datetime.isoformat()` timestamp
//! rendering. The emitted document is an order-preserving [`JsonVal`] so its
//! compact serialization matches v1's opensearch-py output exactly.

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, TimeZone as _, Timelike as _, Utc};

use crate::jsonord::{JsonVal, truncate_chars};

/// OCSF metadata schema version stamped on every event (v1 `"1.3.0"`).
const OCSF_VERSION: &str = "1.3.0";

/// A record that could not be normalized — v1 raised an uncaught exception
/// (`AttributeError` on a non-dict record; `OverflowError`/`OSError` on an
/// out-of-range numeric timestamp), which aiohttp turned into a 500.
#[derive(Debug, thiserror::Error)]
#[error("record cannot be normalized (v1 raised → HTTP 500)")]
pub struct NormalizeError;

/// Maps `class_uid` to the OCSF class name (v1 `OCSF_CLASSES`, default
/// `"unknown"`).
fn class_name(class_uid: i64) -> &'static str {
    match class_uid {
        2001 => "security_finding",
        3002 => "authentication",
        4001 => "network_activity",
        4003 => "file_activity",
        6003 => "api_activity",
        _ => "unknown",
    }
}

/// v1 `_detect_class`: source-substring and field-presence heuristics, checked
/// in the exact same order so ties resolve identically.
fn detect_class(record: &JsonVal, source: &str) -> i64 {
    let event_type_auth = record.get("event_type").and_then(JsonVal::as_str) == Some("auth");
    if source.contains("login") || event_type_auth {
        3002
    } else if source.contains("network") || record.get("src_ip").is_some() {
        4001
    } else if source.contains("file") || record.get("file_path").is_some() {
        4003
    } else if source.contains("api") || record.get("endpoint").is_some() {
        6003
    } else {
        2001
    }
}

/// First truthy value among `keys`, mirroring Python's `a or b or ...` chain.
fn first_truthy<'a>(record: &'a JsonVal, keys: &[&str]) -> Option<&'a JsonVal> {
    keys.iter()
        .filter_map(|k| record.get(k))
        .find(|v| v.py_truthy())
}

/// v1 `_detect_severity`: `str(level or severity or "").lower()` mapped to an
/// OCSF severity id, defaulting to 0 (Unknown).
fn detect_severity(record: &JsonVal) -> i64 {
    let level = first_truthy(record, &["level", "severity"])
        .map(JsonVal::py_str_lower)
        .unwrap_or_default();
    match level.as_str() {
        "debug" | "info" | "informational" => 1,
        "low" | "warning" | "warn" => 2,
        "medium" => 3,
        "error" | "high" => 4,
        "critical" | "fatal" => 5,
        _ => 0,
    }
}

/// v1 `_detect_status`: substring checks over `str(status or result or "")`,
/// defaulting to 99 (Other). Substring semantics are preserved verbatim (e.g.
/// `"revoked"` contains `"ok"` → Success, a v1 quirk).
fn detect_status(record: &JsonVal) -> i64 {
    let status = first_truthy(record, &["status", "result"])
        .map(JsonVal::py_str_lower)
        .unwrap_or_default();
    if status.contains("success") || status.contains("ok") {
        1
    } else if status.contains("fail") || status.contains("error") || status.contains("denied") {
        2
    } else {
        99
    }
}

/// v1 `message = raw.get("message") or raw.get("msg") or str(raw)[:500]`. The
/// truthy `message`/`msg` value is used as-is (any JSON type); otherwise the
/// Python `str(dict)` repr truncated to 500 code points.
fn detect_message(record: &JsonVal) -> JsonVal {
    match first_truthy(record, &["message", "msg"]) {
        Some(v) => v.clone(),
        None => JsonVal::Str(truncate_chars(&record.py_repr(), 500)),
    }
}

/// An event timestamp mirroring the Python `datetime` produced by v1
/// `normalize`: either naive (parsed ISO without offset) or offset-aware
/// (parsed ISO with offset, `fromtimestamp(..., utc)`, or the `now` fallback).
#[derive(Debug, Clone, PartialEq)]
enum EventTime {
    /// Naive datetime — renders without a UTC offset suffix.
    Naive(NaiveDateTime),
    /// Offset-aware datetime — renders with `+HH:MM`.
    Offset(DateTime<FixedOffset>),
}

impl EventTime {
    /// Renders `datetime.isoformat()`: `YYYY-MM-DDTHH:MM:SS`, a 6-digit
    /// fractional part only when microseconds are non-zero, and the UTC offset
    /// only when the datetime is aware.
    fn render(&self) -> String {
        match self {
            // Naive rendering is exactly the shared helper's contract.
            EventTime::Naive(dt) => skauswatch_streams::py_isoformat(*dt),
            EventTime::Offset(dt) => {
                let base = dt.format("%Y-%m-%dT%H:%M:%S");
                let micros = dt.timestamp_subsec_micros();
                let offset = dt.format("%:z");
                if micros == 0 {
                    format!("{base}{offset}")
                } else {
                    format!("{base}.{micros:06}{offset}")
                }
            }
        }
    }
}

/// Truncates a naive datetime to microsecond precision (Python `datetime`
/// resolution).
fn trunc_micros_naive(dt: NaiveDateTime) -> NaiveDateTime {
    let micros = dt.nanosecond() / 1000;
    dt.with_nanosecond(micros * 1000).unwrap_or(dt)
}

/// Truncates an offset datetime to microsecond precision.
fn trunc_micros_offset(dt: DateTime<FixedOffset>) -> DateTime<FixedOffset> {
    let micros = dt.nanosecond() / 1000;
    dt.with_nanosecond(micros * 1000).unwrap_or(dt)
}

/// Reproduces `datetime.fromisoformat(s.replace("Z", "+00:00"))`. Returns
/// `None` when the string is not parseable (v1 falls back to `now`).
fn parse_iso(s: &str) -> Option<EventTime> {
    let s = s.replace('Z', "+00:00");

    if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
        return Some(EventTime::Offset(trunc_micros_offset(dt)));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(EventTime::Naive(trunc_micros_naive(dt)));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(EventTime::Naive(trunc_micros_naive(dt)));
    }
    if let Ok(d) = NaiveDate::parse_from_str(&s, "%Y-%m-%d") {
        return d.and_hms_opt(0, 0, 0).map(EventTime::Naive);
    }
    None
}

/// Reproduces `datetime.fromtimestamp(x, tz=utc)` for a numeric timestamp,
/// rounding floats to the nearest microsecond. Returns an error when the value
/// is out of range (v1 raised → 500).
fn from_unix(n: &serde_json::Number, _now: DateTime<Utc>) -> Result<EventTime, NormalizeError> {
    let (secs, nanos) = if let Some(i) = n.as_i64() {
        (i, 0i64)
    } else if let Some(u) = n.as_u64() {
        (i64::try_from(u).map_err(|_| NormalizeError)?, 0)
    } else if let Some(f) = n.as_f64() {
        let micros = (f * 1_000_000.0).round();
        if !micros.is_finite() {
            return Err(NormalizeError);
        }
        let micros = micros as i128;
        let secs = i64::try_from(micros.div_euclid(1_000_000)).map_err(|_| NormalizeError)?;
        let sub = micros.rem_euclid(1_000_000) as i64;
        (secs, sub * 1000)
    } else {
        return Err(NormalizeError);
    };

    let utc = match Utc.timestamp_opt(secs, u32::try_from(nanos).map_err(|_| NormalizeError)?) {
        chrono::LocalResult::Single(dt) => dt,
        _ => return Err(NormalizeError),
    };
    Ok(EventTime::Offset(utc.fixed_offset()))
}

/// v1 timestamp detection: first truthy of `timestamp`/`time`/`@timestamp`,
/// dispatched by Python type (`str` → ISO parse; `int`/`float`/`bool` →
/// `fromtimestamp`; anything else, or a parse failure → `now`).
fn detect_time(record: &JsonVal, now: DateTime<Utc>) -> Result<EventTime, NormalizeError> {
    let now_aware = || EventTime::Offset(trunc_micros_offset(now.fixed_offset()));
    match first_truthy(record, &["timestamp", "time", "@timestamp"]) {
        Some(JsonVal::Str(s)) => Ok(parse_iso(s).unwrap_or_else(now_aware)),
        Some(JsonVal::Num(n)) => from_unix(n, now),
        // Python `bool` is an `int`; a truthy `True` becomes `fromtimestamp(1)`.
        Some(JsonVal::Bool(true)) => from_unix(&serde_json::Number::from(1), now),
        _ => Ok(now_aware()),
    }
}

/// Normalizes one raw record into the OCSF event document, in the exact v1 key
/// order (`class_uid, class_name, time, severity_id, status_id, message,
/// metadata, raw_data`). `now` supplies the timestamp fallback so the value is
/// deterministic under test.
///
/// # Errors
/// Returns [`NormalizeError`] for inputs that crashed v1 (non-object record or
/// out-of-range numeric timestamp) so the handler can answer 500.
pub fn normalize(
    record: &JsonVal,
    source: &str,
    now: DateTime<Utc>,
) -> Result<JsonVal, NormalizeError> {
    if !record.is_object() {
        // v1 `raw.get(...)` on a non-dict → AttributeError → 500.
        return Err(NormalizeError);
    }

    let class_uid = detect_class(record, source);
    let time = detect_time(record, now)?;
    let metadata = JsonVal::Obj(vec![
        ("version".to_owned(), JsonVal::Str(OCSF_VERSION.to_owned())),
        (
            "product".to_owned(),
            JsonVal::Obj(vec![
                ("name".to_owned(), JsonVal::Str("SkausWatch".to_owned())),
                (
                    "vendor_name".to_owned(),
                    JsonVal::Str("PenguinTech".to_owned()),
                ),
            ]),
        ),
    ]);

    Ok(JsonVal::Obj(vec![
        ("class_uid".to_owned(), JsonVal::Num(class_uid.into())),
        (
            "class_name".to_owned(),
            JsonVal::Str(class_name(class_uid).to_owned()),
        ),
        ("time".to_owned(), JsonVal::Str(time.render())),
        (
            "severity_id".to_owned(),
            JsonVal::Num(detect_severity(record).into()),
        ),
        (
            "status_id".to_owned(),
            JsonVal::Num(detect_status(record).into()),
        ),
        ("message".to_owned(), detect_message(record)),
        ("metadata".to_owned(), metadata),
        ("raw_data".to_owned(), record.clone()),
    ]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::jsonord::from_slice;

    fn fixed_now() -> DateTime<Utc> {
        match Utc.with_ymd_and_hms(2030, 3, 4, 5, 6, 7) {
            chrono::LocalResult::Single(dt) => dt,
            _ => panic!("valid fixed now"),
        }
    }

    fn parse(s: &str) -> JsonVal {
        from_slice(s.as_bytes()).unwrap()
    }

    fn time_of(record: &str) -> String {
        match detect_time(&parse(record), fixed_now()) {
            Ok(t) => t.render(),
            Err(e) => panic!("detect_time: {e}"),
        }
    }

    #[test]
    fn class_detection_matches_v1_field_heuristics() {
        assert_eq!(detect_class(&parse(r#"{"event_type":"auth"}"#), "x"), 3002);
        assert_eq!(detect_class(&parse(r#"{"src_ip":"1.2.3.4"}"#), "x"), 4001);
        assert_eq!(detect_class(&parse(r#"{"file_path":"/e"}"#), "x"), 4003);
        assert_eq!(detect_class(&parse(r#"{"endpoint":"/e"}"#), "x"), 6003);
        assert_eq!(detect_class(&parse("{}"), "x"), 2001);
        // source substrings
        assert_eq!(detect_class(&parse("{}"), "login"), 3002);
        assert_eq!(detect_class(&parse("{}"), "network"), 4001);
        assert_eq!(detect_class(&parse("{}"), "file"), 4003);
        assert_eq!(detect_class(&parse("{}"), "api"), 6003);
    }

    #[test]
    fn severity_mapping_and_falsy_level_fallback() {
        assert_eq!(detect_severity(&parse(r#"{"level":"info"}"#)), 1);
        assert_eq!(detect_severity(&parse(r#"{"severity":"HIGH"}"#)), 4);
        assert_eq!(detect_severity(&parse(r#"{"level":"critical"}"#)), 5);
        // Empty level ("") is falsy → falls through to severity.
        assert_eq!(
            detect_severity(&parse(r#"{"level":"","severity":"medium"}"#)),
            3
        );
        assert_eq!(detect_severity(&parse(r#"{"level":"trace"}"#)), 0);
        assert_eq!(detect_severity(&parse("{}")), 0);
    }

    #[test]
    fn status_substring_semantics_match_v1() {
        assert_eq!(detect_status(&parse(r#"{"status":"success"}"#)), 1);
        assert_eq!(detect_status(&parse(r#"{"status":"OK"}"#)), 1);
        assert_eq!(detect_status(&parse(r#"{"result":"error"}"#)), 2);
        assert_eq!(detect_status(&parse(r#"{"status":"denied"}"#)), 2);
        assert_eq!(detect_status(&parse("{}")), 99);
    }

    #[test]
    fn timestamp_rendering_matches_python_isoformat() {
        // Values captured from datetime.isoformat() — tests/fixtures/isoformat_cases.json.
        assert_eq!(
            time_of(r#"{"timestamp":"2025-01-15T12:30:00Z"}"#),
            "2025-01-15T12:30:00+00:00"
        );
        assert_eq!(
            time_of(r#"{"timestamp":"2025-01-15T12:30:00+05:00"}"#),
            "2025-01-15T12:30:00+05:00"
        );
        assert_eq!(
            time_of(r#"{"timestamp":"2025-01-15T12:30:00.250+05:00"}"#),
            "2025-01-15T12:30:00.250000+05:00"
        );
        assert_eq!(
            time_of(r#"{"timestamp":"2025-01-15T12:30:00"}"#),
            "2025-01-15T12:30:00"
        );
        assert_eq!(
            time_of(r#"{"timestamp":"2025-01-15T12:30:00.5"}"#),
            "2025-01-15T12:30:00.500000"
        );
        assert_eq!(
            time_of(r#"{"timestamp":"2025-01-15"}"#),
            "2025-01-15T00:00:00"
        );
        assert_eq!(
            time_of(r#"{"time":1705312200}"#),
            "2024-01-15T09:50:00+00:00"
        );
        assert_eq!(
            time_of(r#"{"time":1705312200.5}"#),
            "2024-01-15T09:50:00.500000+00:00"
        );
        assert_eq!(
            time_of(r#"{"time":1705312200.0}"#),
            "2024-01-15T09:50:00+00:00"
        );
    }

    #[test]
    fn missing_or_unparsable_timestamp_falls_back_to_now() {
        // now = 2030-03-04T05:06:07Z → aware, micros zero → no fraction.
        assert_eq!(time_of("{}"), "2030-03-04T05:06:07+00:00");
        assert_eq!(
            time_of(r#"{"timestamp":"not-a-date"}"#),
            "2030-03-04T05:06:07+00:00"
        );
    }

    #[test]
    fn non_object_record_is_an_error() {
        assert!(normalize(&parse(r#""a string""#), "x", fixed_now()).is_err());
        assert!(normalize(&parse("42"), "x", fixed_now()).is_err());
    }

    #[test]
    fn message_uses_str_dict_fallback_when_absent() {
        let doc = normalize(
            &parse(r#"{"endpoint":"/api/v1/users","method":"GET","time":1705312200}"#),
            "ingest-test",
            fixed_now(),
        )
        .unwrap();
        assert_eq!(
            doc.get("message").and_then(JsonVal::as_str),
            Some("{'endpoint': '/api/v1/users', 'method': 'GET', 'time': 1705312200}")
        );
    }

    #[test]
    fn document_key_order_and_metadata_match_v1() {
        let doc = normalize(&parse(r#"{"message":"m"}"#), "ingest-test", fixed_now()).unwrap();
        let JsonVal::Obj(entries) = &doc else {
            panic!("expected object");
        };
        let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "class_uid",
                "class_name",
                "time",
                "severity_id",
                "status_id",
                "message",
                "metadata",
                "raw_data"
            ]
        );
        assert_eq!(
            doc.get("metadata").map(JsonVal::to_compact_string),
            Some(
                r#"{"version":"1.3.0","product":{"name":"SkausWatch","vendor_name":"PenguinTech"}}"#
                    .to_owned()
            )
        );
    }
}
